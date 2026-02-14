use anyhow::Result;
use tonic::transport::Channel;

pub mod proto {
    tonic::include_proto!("waf_api");
}

pub use proto::waf_management_client::WafManagementClient;
pub use proto::*;

pub async fn connect(addr: String) -> Result<WafManagementClient<Channel>> {
    let client = WafManagementClient::connect(addr).await?;
    Ok(client)
}
