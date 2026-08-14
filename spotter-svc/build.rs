// pattern: Imperative Shell

fn main() -> Result<(), Box<dyn std::error::Error>> {
    spotter_build::embed(spotter_build::BinaryKind::Service)
}
