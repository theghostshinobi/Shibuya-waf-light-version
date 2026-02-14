use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;

use waf_killer_core::config::{
    Config, PolicySource, SourceType, GitAuthConfig,
    git_sync::GitPolicySync,
};

#[tokio::test]
async fn test_end_to_end_git_reload() {
    let _ = env_logger::builder().filter_level(log::LevelFilter::Info).is_test(true).try_init();

    // 1. Setup mock git repo
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().to_path_buf();
    
    // Initialize bare repo to push to? Or just use a local dir as "remote"
    let _repo = git2::Repository::init(&repo_path).unwrap();
    
    // 2. Configure WAF to use it
    let source_config = PolicySource {
        type_: SourceType::Git,
        repo: Some(repo_path.to_string_lossy().to_string()),
        branch: "main".to_string(),
        auth: GitAuthConfig::None,
        poll_interval_seconds: 1,
        files: vec![],
    };

    // 3. Start Git Sync Logic only (we don't start full WAF server to save time/complexity)
    // Integration test should verify that GitPolicySync:
    // a) Clones
    // b) Detects changes
    // c) Sends reload signal
    
    // Clean up previous run if any
    let _ = std::fs::remove_dir_all("policy_repo");
    
    // Override internal path for test?
    // We can't easily override "policy_repo" hardcoded path in GitPolicySync without changing code.
    // So we run with it, ensuring we clean it up.
    
    let (sync, mut rx) = GitPolicySync::new(source_config).await.expect("Failed to init sync");
    
    // We need to commit something to the "remote" repo first so clone works?
    // GitPolicySync `initialize()` tries to clone. If remote is empty, clone might fail or succeed as empty.
    // It's better to having a commit.
    {
        let repo = git2::Repository::open(&repo_path).unwrap();
        let mut index = repo.index().unwrap();
        let id = index.write_tree().unwrap();
        let tree = repo.find_tree(id).unwrap();
        let sig = git2::Signature::now("Tester", "test@test.com").unwrap();
        let commit_oid = repo.commit(Some("HEAD"), &sig, &sig, "Init", &tree, &[]).unwrap();
        
        let commit = repo.find_commit(commit_oid).unwrap();
        repo.branch("main", &commit, true).unwrap();
    }
    
    let sync = Arc::new(sync);
    
    // Explicitly initialize to catch errors early
    println!("Current Dir: {:?}", std::env::current_dir());
    sync.initialize().expect("Explicit initialization failed");
    
    let sync_handle = sync.clone();
    tokio::spawn(async move {
        sync_handle.start_polling().await;
    });
    
    // 4. Verify clone happened
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(std::path::Path::new("policy_repo").exists());
    
    // 5. Push a change to "remote"
    {
        let repo = git2::Repository::open(&repo_path).unwrap();
        let mut index = repo.index().unwrap();
        // Add a file
        std::fs::write(repo_path.join("new_rule.yaml"), "some: content").unwrap();
        index.add_path(std::path::Path::new("new_rule.yaml")).unwrap();
        let id = index.write_tree().unwrap();
        let tree = repo.find_tree(id).unwrap();
        let sig = git2::Signature::now("Tester", "test@test.com").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        let commit_oid = repo.commit(Some("HEAD"), &sig, &sig, "Update rule", &tree, &[&parent]).unwrap();
        
        // Explicitly update 'main' branch to point to new commit
        repo.reference("refs/heads/main", commit_oid, true, "Fast-forward main").unwrap();
    }
    
    // 6. Wait for reload signal
    // It polls every 1s. We wait up to 5s.
    let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
    
    assert!(result.is_ok(), "Timed out waiting for reload signal");
    let msg = result.unwrap();
    assert!(msg.is_some(), "Channel closed unexpectedly");
    let req = msg.unwrap();
    
    println!("Reload triggered by: {}", req.commit_message);
    assert_eq!(req.commit_message, "Update rule");
    
    // Cleanup
    let _ = std::fs::remove_dir_all("policy_repo");
}
