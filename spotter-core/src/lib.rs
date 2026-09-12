//! Shared identity, configuration, and Snipe-IT domain primitives for `SnipeSpotter`.

pub mod config;
pub mod identity;
pub mod ipc;
pub mod monitors;
pub mod smbios;
pub mod snipeit;
pub mod state;
pub mod sync;

pub use config::{
    BLANK_SETTINGS_TOML, CheckinPolicy, LoggingSettings, MonitorSettings, PollingSettings,
    Settings, SettingsValidationError, SnipeItSettings, config_status, poll_duration,
    validate_settings, validate_snipeit_url,
};

pub use identity::{
    COMPANY_NAME, MUTEX_NAME, PIPE_NAME, PRODUCT_NAME, RUNTIME_SERVICE_PRINCIPAL, SERVICE_ACCOUNT,
    SERVICE_NAME, ServiceRuntimeOptions, data_dir,
};
