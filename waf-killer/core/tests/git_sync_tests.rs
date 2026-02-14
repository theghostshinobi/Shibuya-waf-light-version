#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::RwLock;
    use git2::{Repository, Signature};

    use waf_killer_core::config::{
        Config, GitAuthConfig, PolicySource, SourceType,
        git_sync::GitPolicySync,
    };

    fn setup_git_repo(path: &Path) -> Repository {
        let repo = Repository::init(path).expect("Failed to init repo");
        
        // Configure user
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();
        
        // Initial commit with config
        let config_dir = path.join("config");
        std::fs::create_dir(&config_dir).unwrap();
        let config_path = config_dir.join("waf.yaml");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "server:\n  http_port: 8080").unwrap();

        let mut index = repo.index().unwrap();
        index.add_path(Path::new("config/waf.yaml")).unwrap();
        let oid = index.write_tree().unwrap();
        let tree = repo.find_tree(oid).unwrap();
        
        let sig = Signature::now("Test User", "test@example.com").unwrap();
        let commit_oid = repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[]).unwrap();
        
        // Ensure 'main' branch exists
        let commit = repo.find_commit(commit_oid).unwrap();
        repo.branch("main", &commit, true).unwrap();
        
        drop(tree);
        drop(index);
        drop(commit);
        
        repo
    }

    #[tokio::test]
    async fn test_git_sync_initialization() {
        // 1. Setup origin repo
        let origin_dir = TempDir::new().unwrap();
        let _origin_repo = setup_git_repo(origin_dir.path());

        // 2. Configure sync
        let source_config = PolicySource {
            type_: SourceType::Git,
            repo: Some(origin_dir.path().to_string_lossy().to_string()),
            branch: "main".to_string(),
            auth: GitAuthConfig::None,
            poll_interval_seconds: 1,
            files: vec![],
        };

        // 3. Init sync wrapper
        // We override current dir behavior by just checking if it clones to "policy_repo"
        // But since GitPolicySync hardcodes "policy_repo" relative path, we need to run this in a temp dir
        // OR we modify GitPolicySync to accept a base path for testing.
        // For this test, let's just create the struct.
        // Wait, `new` hardcodes "policy_repo". I should probably make that configurable or relative to CWD.
        // Best hack for test: Change CWD for the test?
        // Changing CWD in tests is risky due to concurrency.
        // Better: Modify `new` to take an optional path override?
        // Or just let it clone into "policy_repo" in the current CWD (target/debug/deps/...).
        // But that might dirty the build dir.
        // Let's rely on `GitPolicySync` using `PathBuf::from("policy_repo")` which is relative.
        // If I change CWD for *this test binary*? No.
        
        // Let's modify GitPolicySync to allow overriding path for tests?
        // Or just cleanup "policy_repo" after test.
        
        // Clean up first
        let _ = std::fs::remove_dir_all("policy_repo");
        
        let (sync, _rx) = GitPolicySync::new(source_config).await.expect("Failed to create sync");
        
        // 4. Initialize (Wrapper for clone)
        sync.initialize().expect("Failed to initialize repo");
        
        // 5. Verify it cloned
        assert!(Path::new("policy_repo").exists());
        assert!(Path::new("policy_repo/config/waf.yaml").exists());
        
        // Clean up
        let _ = std::fs::remove_dir_all("policy_repo");
    }
}
