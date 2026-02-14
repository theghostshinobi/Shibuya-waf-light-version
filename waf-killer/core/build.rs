fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(&["proto/threat_intel.proto", "../proto/waf_api.proto"], &["proto", "../proto"])?;
    Ok(())
}
