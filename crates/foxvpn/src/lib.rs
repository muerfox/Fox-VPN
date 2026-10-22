//! Fox-VPN library.
//!
//! The desktop and Android shells share this crate. It owns SSH authentication,
//! the tunnel session, route planning, and the remote helper protocol.
//! Platform shells supply a user interface and, on Android, a `VpnService`
//! file descriptor.

pub mod config;
pub mod control;
pub mod error;
pub mod forward;
pub mod helper_link;
pub mod helper_server;
pub mod hostkey;
pub mod ipcheck;
pub mod platform;
pub mod protocol;
pub mod routes;
pub mod secrets;
pub mod session;
pub mod ssh_link;
pub mod worker;

pub use config::{AppConfig, AuthMethod, Profile, RoutingMode, TransportMode};
pub use control::{ControlEvent, Decision, HostKeyChoice, PromptSlot, SessionControl};
pub use error::{Error, Result};
pub use session::run_session;
pub use worker::{elevate_and_run, WorkerRequest};

/// Address used on the client virtual interface.
pub const TUN_ADDR: &str = "10.77.0.2";
/// Peer address used when a remote L3 helper creates its own interface.
pub const TUN_PEER: &str = "10.77.0.1";
pub const TUN_PREFIX: u8 = 24;
pub const TUN_NAME: &str = "fox0";
/// fwmark applied to the SSH socket so policy routing cannot loop it into the tunnel.
pub const SSH_MARK: u32 = 0x6670;
/// Policy-routing table that owns tunnel routes. The main table is left intact.
pub const ROUTE_TABLE: u32 = 7660;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
