fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../proto/waf_api.proto")?;
    Ok(())
}
