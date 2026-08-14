// pattern: Imperative Shell

//! Windows executable resource generation for `SnipeSpotter` build scripts.

use std::{env, fs, path::PathBuf};

/// Manifest privilege level for a product binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryKind {
    /// Windows service process, launched by SCM as `LocalSystem`.
    Service,
    /// Operator CLI, which requires administrator privileges.
    Cli,
}

/// Generate and compile VERSIONINFO plus an executable manifest for a Windows target.
///
/// Product and company identity are read from `spotter-core/src/identity.rs`, making that file the
/// sole source of truth. Non-Windows targets emit rerun directives but do not invoke an RC compiler.
///
/// # Errors
///
/// Returns an error when build environment variables are absent, identity cannot be parsed,
/// generated files cannot be written, or resource compilation fails.
pub fn embed(kind: BinaryKind) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let identity_path = manifest_dir.join("../spotter-core/src/identity.rs");
    println!("cargo:rerun-if-changed={}", identity_path.display());
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");
    if env::var("CARGO_CFG_TARGET_OS")? != "windows" {
        return Ok(());
    }
    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;
    if target_env != "msvc" {
        println!(
            "cargo:warning=Windows resources are embedded only for the supported MSVC target; skipping target environment {target_env}"
        );
        return Ok(());
    }

    let identity = fs::read_to_string(&identity_path)?;
    let product_name = parse_string_constant(&identity, "PRODUCT_NAME")?;
    let company_name = parse_string_constant(&identity, "COMPANY_NAME")?;
    let version = env::var("CARGO_PKG_VERSION")?;
    let numeric_version = numeric_version(&version)?;
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let manifest_path = out_dir.join("spotter.manifest");
    let rc_path = out_dir.join("spotter.rc");
    fs::write(&manifest_path, manifest(kind))?;
    fs::write(
        &rc_path,
        resource_script(
            &manifest_path,
            &product_name,
            &company_name,
            &version,
            numeric_version,
        ),
    )?;

    embed_resource::compile(&rc_path, embed_resource::NONE)
        .manifest_required()
        .map_err(|error| format!("failed to compile Windows resources: {error:?}"))?;
    Ok(())
}

fn parse_string_constant(source: &str, name: &str) -> Result<String, String> {
    let prefix = format!("pub const {name}: &str = \"");
    let value = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .and_then(|value| value.strip_suffix("\";"))
        .ok_or_else(|| format!("failed to parse {name} from identity.rs"))?;
    if value.is_empty() || value.contains(['"', '\\']) {
        return Err(format!("{name} contains unsupported resource characters"));
    }
    Ok(value.to_owned())
}

fn numeric_version(version: &str) -> Result<[u16; 4], String> {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts = core.split('.');
    let major = parse_version_part(parts.next(), "major")?;
    let minor = parse_version_part(parts.next(), "minor")?;
    let patch = parse_version_part(parts.next(), "patch")?;
    if parts.next().is_some() {
        return Err(format!(
            "version has more than three numeric parts: {version}"
        ));
    }
    Ok([major, minor, patch, 0])
}

fn parse_version_part(value: Option<&str>, label: &str) -> Result<u16, String> {
    value
        .ok_or_else(|| format!("version is missing {label} component"))?
        .parse::<u16>()
        .map_err(|_| format!("version {label} component is not a u16"))
}

fn manifest(kind: BinaryKind) -> &'static str {
    let level = match kind {
        BinaryKind::Service => "asInvoker",
        BinaryKind::Cli => "requireAdministrator",
    };
    match level {
        "asInvoker" => include_str!("service.manifest.xml"),
        _ => include_str!("cli.manifest.xml"),
    }
}

fn resource_script(
    manifest_path: &std::path::Path,
    product: &str,
    company: &str,
    version: &str,
    numeric: [u16; 4],
) -> String {
    let manifest = manifest_path.display().to_string().replace('\\', "\\\\");
    format!(
        "1 24 \"{manifest}\"\n1 VERSIONINFO\nFILEVERSION {a},{b},{c},{d}\nPRODUCTVERSION {a},{b},{c},{d}\nFILEFLAGSMASK 0x3fL\nFILEFLAGS 0x0L\nFILEOS 0x40004L\nFILETYPE 0x1L\nFILESUBTYPE 0x0L\nBEGIN\n  BLOCK \"StringFileInfo\"\n  BEGIN\n    BLOCK \"040904b0\"\n    BEGIN\n      VALUE \"CompanyName\", \"{company}\\0\"\n      VALUE \"FileDescription\", \"{product}\\0\"\n      VALUE \"FileVersion\", \"{version}\\0\"\n      VALUE \"ProductName\", \"{product}\\0\"\n      VALUE \"ProductVersion\", \"{version}\\0\"\n    END\n  END\n  BLOCK \"VarFileInfo\"\n  BEGIN\n    VALUE \"Translation\", 0x409, 1200\n  END\nEND\n",
        a = numeric[0],
        b = numeric[1],
        c = numeric[2],
        d = numeric[3],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_and_semver() -> Result<(), String> {
        let source = "pub const PRODUCT_NAME: &str = \"SnipeSpotter\";\n";
        assert_eq!(
            parse_string_constant(source, "PRODUCT_NAME")?,
            "SnipeSpotter"
        );
        assert_eq!(numeric_version("1.2.3-rc.1")?, [1, 2, 3, 0]);
        assert!(numeric_version("1.2").is_err());
        Ok(())
    }

    #[test]
    fn resource_contains_identity_and_version() {
        let rc = resource_script(
            std::path::Path::new(r"C:\\out\\spotter.manifest"),
            "SnipeSpotter",
            "infogyre",
            "1.2.3",
            [1, 2, 3, 0],
        );
        assert!(rc.contains("CompanyName"));
        assert!(rc.contains("infogyre"));
        assert!(rc.contains("FILEVERSION 1,2,3,0"));
    }
}
