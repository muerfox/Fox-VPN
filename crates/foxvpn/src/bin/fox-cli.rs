use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use foxvpn::config::{self, AppConfig, AuthMethod};
use foxvpn::control::{ControlEvent, Decision, HostKeyChoice, PromptSlot, SessionControl};
use foxvpn::secrets::{self, SecretStore, SessionSecrets, SystemStore};
use foxvpn::worker::WorkerRequest;
use foxvpn::{self, platform};

#[derive(Parser)]
#[command(name = "fox-cli", version, about = "Fox-VPN command line")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect using a saved profile. Elevates when route changes are required.
    Connect {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Trust a previously unseen host key. A changed key is still rejected.
        #[arg(long)]
        accept_new_host_key: bool,
    },
    /// Root-side worker. Invoked by the application, not by users.
    Worker {
        #[arg(long)]
        socket: PathBuf,
    },
    /// Remove routes, DNS changes, and kill-switch rules left by a crashed session.
    Repair,
    /// Print the config path and profile names.
    Profiles,
    /// Validate a YAML file, including the example single-profile form.
    Check {
        path: PathBuf,
    },
}

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    let _ = tracing_log::LogTracer::init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Connect { profile, config, accept_new_host_key } => {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(connect(profile, config, accept_new_host_key))
        }
        Command::Worker { socket } => {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(foxvpn::worker::run_worker(&socket))
        }
        Command::Repair => {
            if !platform::is_elevated() {
                Err(foxvpn::error::needs_elevation())
            } else {
                platform::repair()
            }
        }
        Command::Profiles => {
            let cfg = config::load_config(&config::config_path()).unwrap_or_default();
            println!("{}", config::config_path().display());
            for profile in cfg.profiles {
                println!("{}  {}  {}", profile.id, profile.name, profile.endpoint());
            }
            Ok(())
        }
        Command::Check { path } => {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("read failed: {e}");
                std::process::exit(1);
            });
            match config::parse_config_yaml(&text) {
                Ok(cfg) => {
                    println!("profiles: {}", cfg.profiles.len());
                    for profile in &cfg.profiles {
                        if let Err(err) = config::validate_profile(profile) {
                            println!("{}: {err}", profile.name);
                        } else {
                            println!("{}: ok", profile.name);
                        }
                    }
                    Ok(())
                }
                Err(err) => Err(foxvpn::Error::fatal(err, "The file was not loaded.")),
            }
        }
    };
    if let Err(err) = result {
        eprintln!("error: {}", err.message());
        eprintln!("{}", err.hint());
        std::process::exit(1);
    }
}

async fn connect(name: String, config_path: Option<PathBuf>, accept_new: bool) -> foxvpn::Result<()> {
    let path = config_path.unwrap_or_else(config::config_path);
    let cfg = config::load_config(&path)?;
    let profile = cfg
        .profiles
        .into_iter()
        .find(|p| p.name == name || p.id == name)
        .ok_or_else(|| foxvpn::Error::fatal(format!("no profile named {name}"), "Create the profile in the application or import a YAML file."))?;
    config::validate_profile(&profile).map_err(|e| foxvpn::Error::fatal(e, "Fix the profile before connecting."))?;
    let secrets = load_secrets(&profile)?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let prompt = PromptSlot::default();
    let cancel = Arc::new(AtomicBool::new(false));
    let control = SessionControl::new(tx, prompt.clone(), cancel.clone());
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel.store(true, Ordering::Relaxed);
    });
    let ui = control.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                ControlEvent::Log { level, msg } => println!("[{level}] {msg}"),
                ControlEvent::Status { status } => println!("status: {status}"),
                ControlEvent::Stats { up, down } => println!("stats: up={up} down={down}"),
                ControlEvent::PublicIp { phase, value } => println!("public ip ({phase}): {value}"),
                ControlEvent::Error { message, hint } => {
                    eprintln!("error: {message}");
                    eprintln!("{hint}");
                }
                ControlEvent::HostKeyPrompt { fingerprint, changed } => {
                    if changed && !accept_new {
                        eprintln!("host key changed: {fingerprint}");
                        prompt.resolve(HostKeyChoice::Reject);
                    } else if accept_new && !changed {
                        println!("trusting new host key {fingerprint}");
                        prompt.resolve(HostKeyChoice::TrustNew);
                    } else {
                        eprintln!("host key requires a decision: {fingerprint} changed={changed}");
                        eprintln!("re-run with --accept-new-host-key to trust an unseen key");
                        prompt.resolve(HostKeyChoice::Reject);
                    }
                }
                ControlEvent::Info { transport, server } => println!("connected {server} via {transport}"),
                ControlEvent::Exit { code } => println!("exit {code}"),
            }
        }
    });
    let owner = platform::current_owner().unwrap_or((0, 0));
    let request = WorkerRequest {
        profile,
        password: secrets.password.as_ref().map(|s| s.to_string()),
        passphrase: secrets.passphrase.as_ref().map(|s| s.to_string()),
        socks_password: secrets.socks_password.as_ref().map(|s| s.to_string()),
        jump_password: secrets.jump_password.as_ref().map(|s| s.to_string()),
        jump_passphrase: secrets.jump_passphrase.as_ref().map(|s| s.to_string()),
        accept_new_host_key: accept_new,
        known_hosts: config::known_hosts_path(),
        owner_uid: owner.0,
        owner_gid: owner.1,
    };
    let _ = Decision::Disconnect;
    let _ = AppConfig::default();
    foxvpn::elevate_and_run(request, ui).await
}

fn load_secrets(profile: &foxvpn::Profile) -> foxvpn::Result<SessionSecrets> {
    let store = SystemStore;
    let mut secrets = SessionSecrets::default();
    match profile.authentication {
        AuthMethod::Password => {
            secrets.password = env_or_store("FOX_VPN_PASSWORD", &store, &secrets::account(&profile.id, "password"))?;
            if secrets.password.is_none() {
                return Err(foxvpn::error::auth_failed("no password in FOX_VPN_PASSWORD or the system keyring"));
            }
        }
        AuthMethod::PrivateKeyPassphrase => {
            secrets.passphrase = env_or_store("FOX_VPN_PASSPHRASE", &store, &secrets::account(&profile.id, "passphrase"))?;
        }
        AuthMethod::PrivateKey => {}
    }
    if profile.socks.as_ref().and_then(|s| s.username.as_ref()).is_some() {
        secrets.socks_password = env_or_store("FOX_VPN_SOCKS_PASSWORD", &store, &secrets::account(&profile.id, "socks"))?;
    }
    Ok(secrets)
}

fn env_or_store(var: &str, store: &SystemStore, account: &str) -> foxvpn::Result<Option<Zeroizing<String>>> {
    if let Ok(value) = std::env::var(var) {
        if !value.is_empty() {
            return Ok(Some(Zeroizing::new(value)));
        }
    }
    match store.get(account) {
        Ok(Some(value)) => Ok(Some(Zeroizing::new(value))),
        Ok(None) => Ok(None),
        Err(err) => Err(foxvpn::Error::fatal(err, "Unlock the system keyring and try again. The secret was not written to the profile file.")),
    }
}
