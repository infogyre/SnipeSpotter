#![cfg(windows)]

//! Windows API integration boundary for `SnipeSpotter`.

// pattern: Imperative Shell

pub mod dpapi;
pub mod elevation;
pub mod mutex;
pub mod pipe;
