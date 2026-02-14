fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(&["../proto/waf_api.proto"], &["../proto"])?;
    Ok(())
}
