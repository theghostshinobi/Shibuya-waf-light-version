use crate::config::UpstreamConfig;
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;
use url::Url;
use std::net::SocketAddr;

pub struct UpstreamPool {
    config: UpstreamConfig,
    addr: SocketAddr,
    tls: bool,
    sni: String,
}

impl UpstreamPool {
    pub fn new(config: UpstreamConfig) -> Self {
        // Parse backend_url to extract host, port, scheme
        let url = Url::parse(&config.backend_url)
            .expect("Invalid backend_url format");
        
        let host = url.host_str().unwrap_or("localhost").to_string();
        let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let tls = url.scheme() == "https";
        let sni = if tls { host.clone() } else { String::new() };
        
        let addr = format!("{}:{}", host, port)
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| {
                // If host is not an IP, use DNS resolution would happen at connection time
                // For now, fallback to localhost
                "127.0.0.1:80".parse().unwrap()
            });

        Self { config, addr, tls, sni }
    }

    pub fn get_peer(&self) -> Result<HttpPeer> {
        let mut peer = HttpPeer::new(self.addr, self.tls, self.sni.clone());

        // Configure timeouts from config
        peer.options.connection_timeout = Some(self.config.connect_timeout);

        Ok(peer)
    }
    
    pub fn backend_url(&self) -> &str {
        &self.config.backend_url
    }
}
