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

/// Runtime identities used by an installed service process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRuntimeOptions {
    /// SCM service name and service-dispatcher identity.
    pub service_name: String,
    /// Root directory for settings, state, journals, and logs.
    pub data_root: PathBuf,
    /// Named-pipe endpoint used by the service IPC server.
    pub pipe_endpoint: String,
    /// Global mutex name used to prevent duplicate service processes.
    pub mutex_name: String,
}

impl ServiceRuntimeOptions {
    /// Construct a validated runtime identity for an isolated service instance.
    ///
    /// # Errors
    /// Returns an error when an identity is empty, contains a NUL byte, or does not use the
    /// Windows named-pipe namespace.
    pub fn new(
        service_name: impl Into<String>,
        data_root: PathBuf,
        pipe_endpoint: impl Into<String>,
        mutex_name: impl Into<String>,
    ) -> Result<Self, String> {
        let options = Self {
            service_name: service_name.into(),
            data_root,
            pipe_endpoint: pipe_endpoint.into(),
            mutex_name: mutex_name.into(),
        };
        options.validate()?;
        Ok(options)
    }

    /// Return the fixed production runtime identity.
    #[must_use]
    pub fn production() -> Self {
        Self {
            service_name: String::from(SERVICE_NAME),
            data_root: data_dir(),
            pipe_endpoint: String::from(PIPE_NAME),
            mutex_name: String::from(MUTEX_NAME),
        }
    }

    /// Encode the identity as service launch arguments.
    #[must_use]
    pub fn launch_arguments(&self) -> Vec<String> {
        vec![
            String::from("--service-name"),
            self.service_name.clone(),
            String::from("--data-root"),
            self.data_root.to_string_lossy().into_owned(),
            String::from("--pipe-endpoint"),
            self.pipe_endpoint.clone(),
            String::from("--mutex-name"),
            self.mutex_name.clone(),
        ]
    }

    /// Decode service launch arguments, using production defaults when no arguments are present.
    ///
    /// # Errors
    /// Returns an error when arguments are incomplete, duplicated, unknown, or invalid.
    pub fn from_arguments(arguments: &[String]) -> Result<Self, String> {
        if arguments.is_empty() {
            return Ok(Self::production());
        }
        if arguments.len() != 8 {
            return Err(String::from(
                "service runtime arguments must contain four option pairs",
            ));
        }
        let mut values: [Option<String>; 4] = [None, None, None, None];
        for pair in arguments.chunks_exact(2) {
            let index = match pair[0].as_str() {
                "--service-name" => 0,
                "--data-root" => 1,
                "--pipe-endpoint" => 2,
                "--mutex-name" => 3,
                _ => return Err(format!("unknown service runtime argument: {}", pair[0])),
            };
            if values[index].replace(pair[1].clone()).is_some() {
                return Err(format!("duplicate service runtime argument: {}", pair[0]));
            }
        }
        let [
            Some(service_name),
            Some(data_root),
            Some(pipe_endpoint),
            Some(mutex_name),
        ] = values
        else {
            return Err(String::from("service runtime arguments are incomplete"));
        };
        Self::new(
            service_name,
            PathBuf::from(data_root),
            pipe_endpoint,
            mutex_name,
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.service_name.trim().is_empty() {
            return Err(String::from("service name must not be empty"));
        }
        if self.data_root.as_os_str().is_empty() {
            return Err(String::from("service data root must not be empty"));
        }
        if self.pipe_endpoint.trim().is_empty() {
            return Err(String::from("pipe endpoint must not be empty"));
        }
        if !self.pipe_endpoint.starts_with(r"\\.\pipe\") {
            return Err(String::from(
                "pipe endpoint must use the Windows named-pipe namespace",
            ));
        }
        if self.mutex_name.trim().is_empty() {
            return Err(String::from("mutex name must not be empty"));
        }
        if self.service_name.contains('\0')
            || self.pipe_endpoint.contains('\0')
            || self.mutex_name.contains('\0')
            || self.data_root.to_string_lossy().contains('\0')
        {
            return Err(String::from(
                "service runtime identity must not contain NUL bytes",
            ));
        }
        Ok(())
    }
}

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
    fn runtime_options_round_trip_through_launch_arguments() {
        let options = ServiceRuntimeOptions::new(
            "SnipeSpotter-test",
            PathBuf::from(r"C:\\Temp\\SnipeSpotter-test"),
            r"\\.\pipe\SnipeSpotter-test",
            "Global\\SnipeSpotter-test",
        )
        .expect("test runtime identity must be valid");

        let arguments = options.launch_arguments();
        assert_eq!(
            ServiceRuntimeOptions::from_arguments(&arguments),
            Ok(options)
        );
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
