use anyhow::{Result, Context};
use git2::{Repository, ResetType, Oid};
use std::path::{Path, PathBuf};
use tracing::{info, error};
use crate::config::policy_schema::Policy;
use super::validator::{validate_against_schema, validate_semantic};

pub struct PolicyLoader {
    pub repo_path: PathBuf,
    repo: Repository,
    #[allow(dead_code)]
    current_commit: Option<Oid>, // useful for version tracking
}

impl PolicyLoader {
    pub fn new(repo_url: &str, local_path: &Path) -> Result<Self> {
        info!("Initializing Policy Loader: {} -> {:?}", repo_url, local_path);
        
        let repo = if local_path.join(".git").exists() {
            info!("Opening existing repository at {:?}", local_path);
            Repository::open(local_path).context("Failed to open existing repository")?
        } else {
            info!("Cloning repository from {} to {:?}", repo_url, local_path);
            Repository::clone(repo_url, local_path).context("Failed to clone repository")?
        };
        
        Ok(Self {
            repo_path: local_path.to_path_buf(),
            repo,
            current_commit: None,
        })
    }
    
    pub fn from_path(local_path: &Path) -> Result<Self> {
         let repo = Repository::open(local_path).context("Failed to open repository")?;
         Ok(Self {
             repo_path: local_path.to_path_buf(),
             repo,
             current_commit: None,
         })
    }
    
    pub fn load_policy(&mut self) -> Result<Policy> {
        info!("Loading policy...");
        
        // Pull latest changes
        if let Err(e) = self.pull_latest() {
            error!("Failed to pull latest changes: {}. Using current local version.", e);
        }
        
        // Read policy.yaml
        let policy_path = self.repo_path.join("policy.yaml");
        if !policy_path.exists() {
             return Err(anyhow::anyhow!("policy.yaml not found in repository root"));
        }
        
        let policy_content = std::fs::read_to_string(&policy_path)?;
        
        // Parse YAML
        let policy: Policy = serde_yaml::from_str(&policy_content)
            .context("Failed to parse policy.yaml")?;
        
        // Validate
        validate_against_schema(&policy)?;
        validate_semantic(&policy)?;
        
        // Store current commit
        if let Ok(head) = self.repo.head() {
            self.current_commit = head.target();
        }
        
        info!("Policy loaded successfully (version: {})", policy.version);
        Ok(policy)
    }
    
    fn pull_latest(&mut self) -> Result<()> {
        // Fetch from remote
        let mut remote = self.repo.find_remote("origin")
            .context("Failed to find 'origin' remote")?;
            
        remote.fetch(&["main"], None, None)
            .context("Failed to fetch from origin")?;
            
        // Reset to origin/main (hard reset)
        let fetch_head = self.repo.find_reference("FETCH_HEAD")?;
        let fetch_commit = self.repo.reference_to_annotated_commit(&fetch_head)?;
        let object = self.repo.find_object(fetch_commit.id(), None)?;
        
        self.repo.reset(
            &object,
            ResetType::Hard,
            None,
        ).context("Failed to hard reset to FETCH_HEAD")?;
        
        Ok(())
    }
}
