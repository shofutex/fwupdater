use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("failed to parse Vultr response: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Vultr API returned an error (HTTP {status}): {message}")]
    Api { status: u16, message: String },

    #[error("could not determine public IP address: {0}")]
    IpDetect(String),
}

pub type Result<T> = std::result::Result<T, Error>;
