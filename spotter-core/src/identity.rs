//! Stable product and service identity values.

// pattern: Functional Core

use std::path::PathBuf;

pub const PRODUCT_NAME: &str = "SnipeSpotter";
pub const COMPANY_NAME: &str = "infogyre";
pub const SERVICE_NAME: &str = PRODUCT_NAME;
pub const SERVICE_ACCOUNT: &str = "LocalSystem";
pub const RUNTIME_SERVICE_PRINCIPAL: &str = r"NT AUTHORITY\SYSTEM";
pub const PIPE_NAME: &str = r"\\.\pipe\SnipeSpotter";
pub const MUTEX_NAME: &str = "Global\\SnipeSpotter";

/// Returns the platform-specific root for `SnipeSpotter` data.
#[must_use]
pub fn data_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData")
            .join(COMPANY_NAME)
            .join(PRODUCT_NAME)
    } else {
        std::env::temp_dir().join(PRODUCT_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_values_are_stable() {
        assert_eq!(PRODUCT_NAME, "SnipeSpotter");
        assert_eq!(COMPANY_NAME, "infogyre");
        assert_eq!(SERVICE_NAME, "SnipeSpotter");
        assert_eq!(SERVICE_ACCOUNT, "LocalSystem");
        assert_eq!(RUNTIME_SERVICE_PRINCIPAL, r"NT AUTHORITY\SYSTEM");
        assert_eq!(PIPE_NAME, r"\\.\pipe\SnipeSpotter");
        assert_eq!(MUTEX_NAME, "Global\\SnipeSpotter");
    }

    #[test]
    fn data_dir_ends_with_product_name() {
        assert!(data_dir().ends_with(PRODUCT_NAME));
    }

    #[cfg(windows)]
    #[test]
    fn windows_data_dir_uses_program_data() {
        assert_eq!(
            data_dir(),
            PathBuf::from(r"C:\ProgramData\infogyre\SnipeSpotter")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_data_dir_uses_temp_dir() {
        assert_eq!(data_dir(), std::env::temp_dir().join(PRODUCT_NAME));
    }
}
