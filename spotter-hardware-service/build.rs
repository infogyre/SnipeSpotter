// pattern: Imperative Shell

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("CARGO_FEATURE_HARDWARE_EXPERIMENT").is_some() {
        spotter_build::embed(spotter_build::BinaryKind::Service)?;
    }
    Ok(())
}
