pub mod error;
pub mod ip_detect;
pub mod planner;
pub mod vultr;

pub use error::{Error, Result};
pub use ip_detect::{detect_all, detect_ipv4, detect_ipv6, DetectedIps};
