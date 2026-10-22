/// Errors that the session supervisor can classify as fatal or retryable.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{message}")]
    Fatal { message: String, hint: String },
    #[error("{message}")]
    Retryable { message: String, hint: String },
    #[error("tunnel stopped")]
    Stopped,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn fatal(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::Fatal {
            message: message.into(),
            hint: hint.into(),
        }
    }

    pub fn retryable(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::Retryable {
            message: message.into(),
            hint: hint.into(),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Fatal { message, .. } | Self::Retryable { message, .. } => message,
            Self::Stopped => "tunnel stopped",
        }
    }

    pub fn hint(&self) -> &str {
        match self {
            Self::Fatal { hint, .. } | Self::Retryable { hint, .. } => hint,
            Self::Stopped => "The disconnect was requested locally.",
        }
    }

    /// Authentication and host-key failures must not be retried automatically.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal { .. })
    }
}

pub fn auth_failed(detail: impl Into<String>) -> Error {
    Error::fatal(
        format!("SSH authentication failed: {}", detail.into()),
        "Check the username, private key, and passphrase. Passwords are read from the system keyring, not from the profile file.",
    )
}

pub fn host_key_rejected(fingerprint: &str, changed: bool) -> Error {
    if changed {
        Error::fatal(
            format!("SSH host key changed ({fingerprint})"),
            "The server key does not match the saved key. This can mean a server reinstall or a man-in-the-middle. Trust the new key only if you verified it out of band.",
        )
    } else {
        Error::fatal(
            format!("SSH host key was not trusted ({fingerprint})"),
            "Fox-VPN does not trust a server on first use unless you explicitly accept the fingerprint.",
        )
    }
}

pub fn unreachable(detail: impl Into<String>) -> Error {
    Error::retryable(
        format!("SSH server is unreachable: {}", detail.into()),
        "Check the host, port, and local network. The tunnel was not started, so traffic is unchanged.",
    )
}

pub fn timed_out() -> Error {
    Error::retryable(
        "Timed out waiting for the SSH server",
        "Increase the connection timeout, or confirm that the port is open and not filtered.",
    )
}

pub fn needs_elevation() -> Error {
    Error::fatal(
        "Administrator privileges are required to create the tunnel device and install routes",
        "Start the connection again and approve the privilege prompt, or run `sudo fox-cli connect --profile <name>`.",
    )
}
