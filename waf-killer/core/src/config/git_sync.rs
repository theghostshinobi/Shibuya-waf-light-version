use crate::config::{GitAuthConfig, PolicySource};
use anyhow::{Context, Result};
use git2::{Cred, FetchOptions, RemoteCallbacks, Repository};
use log::{debug, error, info, warn};
use std::path::{PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};

/// Handles synchronization of policies from a Git repository
#[derive(Clone)]
pub struct GitPolicySync {
    config: PolicySource,
    repo_path: PathBuf,
    #[allow(dead_code)]
    last_commit_hash: Arc<RwLock<Option<String>>>,
    reload_tx: mpsc::Sender<ConfigReloadRequest>,
}

#[derive(Debug, Clone)]
pub struct ConfigReloadRequest {
    pub config_path: PathBuf,
    pub commit_hash: String,
    pub commit_message: String,
    pub commit_author: String,
}

impl GitPolicySync {
    /// Create a new GitPolicySync instance
    pub async fn new(
        source_config: PolicySource,
    ) -> Result<(Self, mpsc::Receiver<ConfigReloadRequest>)> {
        // Use current directory + subfolder for repo
        // This keeps it isolated but predictable
        let repo_path = PathBuf::from("policy_repo");
        
        // Create channel for reload requests
        // Capacity 1 is enough as we don't want to queue multiple reloads usually
        let (tx, rx) = mpsc::channel(1);
        
        Ok((
            Self {
                config: source_config,
                repo_path,
                last_commit_hash: Arc::new(RwLock::new(None)),
                reload_tx: tx,
            },
            rx
        ))
    }

    /// Initialize: clone repo if doesn't exist, or open existing
    pub fn initialize(&self) -> Result<()> {
        if !self.repo_path.exists() {
            info!("Cloning policy repository from {:?} to {:?}", self.config.repo, self.repo_path);
            let url = self.config.repo.as_ref().context("Git repo URL required")?;
            
            let callbacks = self.create_callbacks();
            let mut fetch_opts = FetchOptions::new();
            fetch_opts.remote_callbacks(callbacks);

            let mut builder = git2::build::RepoBuilder::new();
            builder.fetch_options(fetch_opts);
            builder.branch(&self.config.branch);

            builder.clone(url, &self.repo_path)?;
            info!("✅ Repository cloned successfully");
        } else {
            // Validate it's a repo
            let _ = Repository::open(&self.repo_path).context("Failed to open existing git repo")?;
            debug!("Opened existing repository at {:?}", self.repo_path);
        }
        
        Ok(())
    }

    /// Start background polling loop
    pub async fn start_polling(self: Arc<Self>) {
        info!("🚀 Starting Git policy sync (interval: {}s)", self.config.poll_interval_seconds);
        
        // Initial sync attempt
        if let Err(e) = self.initialize() {
            error!("❌ Failed to initialize Git sync: {}", e);
            // We continue, maybe it fixes itself (e.g. network up)
        }

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.poll_interval_seconds));
        
        // Initial load? NO, main.rs loaded from local file.
        // We might want to do an immediate check if remote is ahead?
        // Let's just wait for first tick.
        
        loop {
            interval.tick().await;
            
            match self.poll_once().await {
                Ok(reloaded) => {
                    if reloaded {
                        info!("✅ Policy update detected and reload requested");
                    }
                }
                Err(e) => {
                    error!("❌ Git poll failed: {}", e);
                }
            }
        }
    }

    /// Execute one poll cycle: pull + check + reload if needed
    async fn poll_once(&self) -> Result<bool> {
        // Run blocking git operations in a blocking thread to avoid stalling async runtime
        let this = self.clone(); // Clone Arc for the thread
        
        // We need to return the request if there is one, to send it over channel
        let request = tokio::task::spawn_blocking(move || {
            this.poll_once_blocking()
        }).await??;
        
        if let Some(req) = request {
            // Send reload request
            self.reload_tx.send(req).await.context("Failed to send reload request")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn poll_once_blocking(&self) -> Result<Option<ConfigReloadRequest>> {
        let repo = Repository::open(&self.repo_path).context("Failed to open repo")?;
        
        // 1. Fetch
        let mut remote = repo.find_remote("origin")?;
        let callbacks = self.create_callbacks();
        
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        
        remote.fetch(&[&self.config.branch], Some(&mut fetch_opts), None)?;

        // 2. Check for updates
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let fetch_commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let analysis = repo.merge_analysis(&[&fetch_commit])?;

        if analysis.0.is_up_to_date() {
            debug!("Policy repository is up to date");
            return Ok(None);
        }

        if analysis.0.is_fast_forward() {
            let refname = format!("refs/heads/{}", self.config.branch);
            let mut reference = repo.find_reference(&refname)?;
            
            let old_target = reference.target();
            let new_target = fetch_commit.id();
            
            if old_target == Some(new_target) {
                return Ok(None);
            }
            
            // 3. Pull (Fast-forward)
            reference.set_target(new_target, "Fast-Forward")?;
            repo.set_head(&refname)?;
            repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
            
            let old_hash = old_target.map(|oid| oid.to_string()).unwrap_or_default();
            let new_hash = new_target.to_string();
            info!("📦 Pulled new changes: {} -> {}", &old_hash[..7.min(old_hash.len())], &new_hash[..7]);
            
            let commit = repo.find_commit(new_target)?;
            let request = ConfigReloadRequest {
                config_path: self.repo_path.join("config/waf.yaml"),
                commit_hash: new_hash,
                commit_message: commit.message().unwrap_or("").to_string(),
                commit_author: commit.author().name().unwrap_or("Unknown").to_string(),
            };
            
            Ok(Some(request))
        } else {
            warn!("Runaway history or merge conflict in policy repo. Manual intervention required.");
            Ok(None)
        }
    }

    /// Retrieve commit info
    fn create_callbacks(&self) -> RemoteCallbacks<'_> {
        let mut callbacks = RemoteCallbacks::new();
        
        match &self.config.auth {
            GitAuthConfig::Ssh { ssh_key_path } => {
                let p = ssh_key_path.clone();
                callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                    Cred::ssh_key(
                        username_from_url.unwrap_or("git"),
                        None,
                        &p,
                        None,
                    )
                });
            }
            GitAuthConfig::Https { username, password_env } => {
                let u = username.clone().unwrap_or("git".to_string());
                let env_var = password_env.clone().unwrap_or_default();
                callbacks.credentials(move |_url, _username, _allowed| {
                    let p = std::env::var(&env_var).unwrap_or_default();
                    Cred::userpass_plaintext(&u, &p)
                });
            }
            GitAuthConfig::None => {}
        }
        
        callbacks
    }
}
