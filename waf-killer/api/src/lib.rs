// Minimal API exports - grpc disabled for macOS build
pub mod http;

// Re-export commonly used types
pub use http::{ApiState, create_router};
