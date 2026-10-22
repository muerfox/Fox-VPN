use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyChoice {
    TrustNew,
    Replace,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlEvent {
    Log { level: String, msg: String },
    Status { status: String },
    Stats { up: u64, down: u64 },
    PublicIp { phase: String, value: String },
    HostKeyPrompt { fingerprint: String, changed: bool },
    Error { message: String, hint: String },
    Exit { code: i32 },
    Info { transport: String, server: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    HostKey { accept: bool, replace: bool },
    Disconnect,
}

impl Decision {
    pub fn choice(&self) -> Option<HostKeyChoice> {
        match self {
            Self::HostKey { accept: true, replace: true } => Some(HostKeyChoice::Replace),
            Self::HostKey { accept: true, replace: false } => Some(HostKeyChoice::TrustNew),
            Self::HostKey { accept: false, .. } => Some(HostKeyChoice::Reject),
            Self::Disconnect => None,
        }
    }
}

#[derive(Clone, Default)]
pub struct PromptSlot {
    inner: Arc<Mutex<Option<oneshot::Sender<HostKeyChoice>>>>,
}

impl PromptSlot {
    pub fn arm(&self) -> oneshot::Receiver<HostKeyChoice> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(tx);
        }
        rx
    }

    pub fn resolve(&self, choice: HostKeyChoice) -> bool {
        let Some(tx) = self.inner.lock().ok().and_then(|mut g| g.take()) else {
            return false;
        };
        tx.send(choice).is_ok()
    }
}

#[derive(Clone)]
pub struct SessionControl {
    pub events: tokio::sync::mpsc::UnboundedSender<ControlEvent>,
    pub prompt: PromptSlot,
    pub cancel: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionControl {
    pub fn new(
        events: tokio::sync::mpsc::UnboundedSender<ControlEvent>,
        prompt: PromptSlot,
        cancel: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self { events, prompt, cancel }
    }

    pub fn log(&self, level: &str, msg: impl Into<String>) {
        let msg = msg.into();
        match level {
            "error" => tracing::error!("{msg}"),
            "warn" => tracing::warn!("{msg}"),
            "debug" => tracing::debug!("{msg}"),
            _ => tracing::info!("{msg}"),
        }
        let _ = self.events.send(ControlEvent::Log {
            level: level.into(),
            msg,
        });
    }

    pub fn status(&self, status: &str) {
        let _ = self.events.send(ControlEvent::Status { status: status.into() });
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn ask_host_key(&self, fingerprint: String, changed: bool) -> HostKeyChoice {
        let rx = self.prompt.arm();
        let _ = self.events.send(ControlEvent::HostKeyPrompt {
            fingerprint,
            changed,
        });
        match tokio::time::timeout(std::time::Duration::from_secs(180), rx).await {
            Ok(Ok(choice)) => choice,
            _ => HostKeyChoice::Reject,
        }
    }
}

pub fn backoff(attempt: u32) -> std::time::Duration {
    let shift = attempt.min(4);
    std::time::Duration::from_secs(1u64 << shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(backoff(0).as_secs(), 1);
        assert_eq!(backoff(1).as_secs(), 2);
        assert_eq!(backoff(3).as_secs(), 8);
        assert_eq!(backoff(8).as_secs(), 16);
    }

    #[test]
    fn host_key_choice_mapping_does_not_treat_accept_as_replace() {
        let trust = Decision::HostKey { accept: true, replace: false }.choice();
        let replace = Decision::HostKey { accept: true, replace: true }.choice();
        assert_eq!(trust, Some(HostKeyChoice::TrustNew));
        assert_eq!(replace, Some(HostKeyChoice::Replace));
    }
}
