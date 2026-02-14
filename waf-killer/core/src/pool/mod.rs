pub mod buffer_pool;
pub mod upstream;

// Re-export UpstreamPool to maintain backward compatibility if needed
pub use upstream::UpstreamPool;
