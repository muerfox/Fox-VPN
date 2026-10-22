//! Fox-VPN desktop shell.
//!
//! The window stays on the calling user account so the system keyring works.
//! Route changes are performed by an elevated `fox-cli worker` started with pkexec.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use foxvpn::config::{self, AppConfig, AuthMethod, JumpHost, Profile, RoutingMode, SocksProxy, TransportMode};
use foxvpn::control::{ControlEvent, HostKeyChoice, PromptSlot, SessionControl};
use foxvpn::secrets::{self, SecretStore, SessionSecrets, SystemStore};
use foxvpn::worker::WorkerRequest;
use zeroize::Zeroizing;

enum Screen {
    Main,
    Settings,
}

#[derive(Clone)]
struct PendingPrompt {
    fingerprint: String,
    changed: bool,
}

struct App {
    config: AppConfig,
    screen: Screen,
    selected: usize,
    status: String,
    transport: String,
    logs: VecDeque<(String, String)>,
    up: u64,
    down: u64,
    rate_up: f64,
    rate_down: f64,
    last_sample: Option<(Instant, u64, u64)>,
    connected_at: Option<Instant>,
    ip_before: String,
    ip_after: String,
    error: String,
    hint: String,
    pending_prompt: Option<PendingPrompt>,
    prompt_slot: PromptSlot,
    cancel: Arc<AtomicBool>,
    running: bool,
    events: tokio::sync::mpsc::UnboundedReceiver<ControlEvent>,
    event_tx: tokio::sync::mpsc::UnboundedSender<ControlEvent>,
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    password: String,
    passphrase: String,
    socks_password: String,
    jump_password: String,
    jump_passphrase: String,
    remember_secrets: bool,
    dns_text: String,
    split_text: String,
    key_path_text: String,
    jump_on: bool,
    jump_host: String,
    jump_port: u16,
    jump_user: String,
    jump_key: String,
    socks_on: bool,
    socks_host: String,
    socks_port: u16,
    socks_user: String,
    remote_command: String,
    startup_note: String,
    startup_connect: bool,
    repaint: bool,
}

enum Job {
    Connect { request: WorkerRequest, control: SessionControl },
}

fn main() -> eframe::Result<()> {
    // Many compositors, including this one, do not offer ext-data-control or
    // wlr-data-control. With DISPLAY set, X11 selection works and the Wayland
    // clipboard probe is skipped, so it does not log a failure on startup.
    if std::env::var_os("DISPLAY").is_some() {
        std::env::remove_var("WAYLAND_DISPLAY");
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/fox-vpn-256.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1100.0, 760.0])
        .with_title("Fox-VPN")
        .with_app_id("fox-vpn");
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native("Fox-VPN", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(fox_visuals());
        let mut config = config::load_config(&config::config_path()).unwrap_or_default();
        if config.profiles.is_empty() {
            config.profiles.push(Profile::blank());
            config.active_profile = Some(config.profiles[0].id.clone());
        }
        let selected = config
            .active_profile
            .as_ref()
            .and_then(|id| config.profiles.iter().position(|p| p.id == *id || p.name == *id))
            .unwrap_or(0);
        config.active_profile = Some(config.profiles[selected].id.clone());
        let (event_tx, events) = tokio::sync::mpsc::unbounded_channel();
        let startup_note = if foxvpn::platform::state_exists() {
            "A previous session did not finish restoring the network. Use Repair before connecting.".into()
        } else {
            String::new()
        };
        let startup_connect = config.connect_on_startup;
        let mut app = Self {
            config,
            screen: Screen::Main,
            selected,
            status: "Disconnected".into(),
            transport: String::new(),
            logs: VecDeque::new(),
            up: 0,
            down: 0,
            rate_up: 0.0,
            rate_down: 0.0,
            last_sample: None,
            connected_at: None,
            ip_before: "—".into(),
            ip_after: "—".into(),
            error: String::new(),
            hint: String::new(),
            pending_prompt: None,
            prompt_slot: PromptSlot::default(),
            cancel: Arc::new(AtomicBool::new(false)),
            running: false,
            events,
            event_tx,
            jobs: spawn_worker(),
            password: String::new(),
            passphrase: String::new(),
            socks_password: String::new(),
            jump_password: String::new(),
            jump_passphrase: String::new(),
            remember_secrets: true,
            dns_text: String::new(),
            split_text: String::new(),
            key_path_text: String::new(),
            jump_on: false,
            jump_host: String::new(),
            jump_port: 22,
            jump_user: "root".into(),
            jump_key: String::new(),
            socks_on: false,
            socks_host: String::new(),
            socks_port: 1080,
            socks_user: String::new(),
            remote_command: String::new(),
            startup_note,
            startup_connect,
            repaint: false,
        };
        app.pull_editors();
        app
    }

    fn log(&mut self, level: &str, msg: impl Into<String>) {
        self.logs.push_back((level.into(), msg.into()));
        while self.logs.len() > 400 {
            self.logs.pop_front();
        }
    }

    fn pull_editors(&mut self) {
        let Some(profile) = self.config.profiles.get(self.selected) else { return };
        self.dns_text = profile.dns_servers.join(", ");
        self.split_text = profile.split_routes.join("\n");
        self.key_path_text = profile.key_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        self.remote_command = profile.remote_command.clone().unwrap_or_default();
        if let Some(jump) = &profile.jump {
            self.jump_on = true;
            self.jump_host = jump.host.clone();
            self.jump_port = jump.port;
            self.jump_user = jump.username.clone();
            self.jump_key = jump.key_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        } else {
            self.jump_on = false;
        }
        if let Some(socks) = &profile.socks {
            self.socks_on = true;
            self.socks_host = socks.host.clone();
            self.socks_port = socks.port;
            self.socks_user = socks.username.clone().unwrap_or_default();
        } else {
            self.socks_on = false;
        }
    }

    fn apply_editors(&mut self) {
        let Some(profile) = self.config.profiles.get_mut(self.selected) else { return };
        profile.dns_servers = self
            .dns_text
            .split(|c: char| c == ',' || c == ' ' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        profile.split_routes = self.split_text.lines().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
        profile.key_path = optional_path(&self.key_path_text);
        profile.remote_command = if self.remote_command.trim().is_empty() { None } else { Some(self.remote_command.trim().to_string()) };
        if self.jump_on {
            profile.jump = Some(JumpHost {
                host: self.jump_host.trim().to_string(),
                port: self.jump_port,
                username: if self.jump_user.trim().is_empty() { "root".into() } else { self.jump_user.trim().to_string() },
                authentication: AuthMethod::PrivateKey,
                key_path: optional_path(&self.jump_key),
            });
        } else {
            profile.jump = None;
        }
        if self.socks_on {
            profile.socks = Some(SocksProxy {
                host: self.socks_host.trim().to_string(),
                port: self.socks_port,
                username: if self.socks_user.trim().is_empty() { None } else { Some(self.socks_user.trim().to_string()) },
            });
        } else {
            profile.socks = None;
        }
    }

    fn save(&mut self) -> std::result::Result<(), String> {
        self.apply_editors();
        if let Some(profile) = self.config.profiles.get(self.selected) {
            self.config.active_profile = Some(profile.id.clone());
        }
        self.store_typed_secrets()?;
        config::save_config(&config::config_path(), &self.config).map_err(|e| e.message().to_string())
    }

    fn store_typed_secrets(&mut self) -> std::result::Result<(), String> {
        let Some(profile) = self.config.profiles.get(self.selected) else { return Ok(()) };
        let id = profile.id.clone();
        let store = SystemStore;
        if self.remember_secrets {
            if !self.password.is_empty() {
                store.set(&secrets::account(&id, "password"), &self.password)?;
                self.password.clear();
            }
            if !self.passphrase.is_empty() {
                store.set(&secrets::account(&id, "passphrase"), &self.passphrase)?;
                self.passphrase.clear();
            }
            if !self.socks_password.is_empty() {
                store.set(&secrets::account(&id, "socks"), &self.socks_password)?;
                self.socks_password.clear();
            }
            if !self.jump_password.is_empty() {
                store.set(&secrets::account(&id, "jump-password"), &self.jump_password)?;
                self.jump_password.clear();
            }
            if !self.jump_passphrase.is_empty() {
                store.set(&secrets::account(&id, "jump-passphrase"), &self.jump_passphrase)?;
                self.jump_passphrase.clear();
            }
        }
        Ok(())
    }

    fn secrets_for_connect(&mut self) -> std::result::Result<SessionSecrets, String> {
        let Some(profile) = self.config.profiles.get(self.selected) else {
            return Err("Create a profile first.".into());
        };
        let id = profile.id.clone();
        let auth = profile.authentication;
        let store = SystemStore;
        let mut secrets = SessionSecrets::default();
        match auth {
            AuthMethod::Password => {
                secrets.password = take_or_load(&mut self.password, &store, &secrets::account(&id, "password"), self.remember_secrets, "SSH password")?;
            }
            AuthMethod::PrivateKeyPassphrase => {
                secrets.passphrase = take_or_load(&mut self.passphrase, &store, &secrets::account(&id, "passphrase"), self.remember_secrets, "key passphrase").ok().flatten();
            }
            AuthMethod::PrivateKey => {}
        }
        if !self.socks_password.is_empty() || self.socks_on {
            secrets.socks_password = take_or_load(&mut self.socks_password, &store, &secrets::account(&id, "socks"), self.remember_secrets, "SOCKS password").ok().flatten();
        }
        if self.jump_on {
            secrets.jump_password = take_or_load(&mut self.jump_password, &store, &secrets::account(&id, "jump-password"), self.remember_secrets, "jump password").ok().flatten();
            secrets.jump_passphrase = take_or_load(&mut self.jump_passphrase, &store, &secrets::account(&id, "jump-passphrase"), self.remember_secrets, "jump passphrase").ok().flatten();
        }
        Ok(secrets)
    }

    fn connect(&mut self) {
        if self.running {
            return;
        }
        self.apply_editors();
        let Some(profile) = self.config.profiles.get(self.selected).cloned() else { return };
        if let Err(err) = config::validate_profile(&profile) {
            self.status = "Error".into();
            self.error = err;
            self.hint = "Fix the profile before connecting. Secrets are not stored in the profile file.".into();
            return;
        }
        let secrets = match self.secrets_for_connect() {
            Ok(secrets) => secrets,
            Err(err) => {
                self.status = "Error".into();
                self.error = err;
                self.hint = "Passwords stay in the system keyring or in this window until you connect.".into();
                return;
            }
        };
        if let Err(err) = self.save() {
            self.log("warn", format!("profile was not saved: {err}"));
        }
        self.error.clear();
        self.hint.clear();
        self.ip_before = "…".into();
        self.ip_after = "…".into();
        self.up = 0;
        self.down = 0;
        self.rate_up = 0.0;
        self.rate_down = 0.0;
        self.last_sample = None;
        self.connected_at = None;
        self.transport = profile.transport.label().into();
        self.status = "Connecting".into();
        self.running = true;
        self.repaint = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        self.prompt_slot = PromptSlot::default();
        let control = SessionControl::new(self.event_tx.clone(), self.prompt_slot.clone(), self.cancel.clone());
        let owner = foxvpn::platform::current_owner().unwrap_or((0, 0));
        let request = WorkerRequest {
            profile,
            password: secrets.password.as_ref().map(|s| s.to_string()),
            passphrase: secrets.passphrase.as_ref().map(|s| s.to_string()),
            socks_password: secrets.socks_password.as_ref().map(|s| s.to_string()),
            jump_password: secrets.jump_password.as_ref().map(|s| s.to_string()),
            jump_passphrase: secrets.jump_passphrase.as_ref().map(|s| s.to_string()),
            accept_new_host_key: false,
            known_hosts: config::known_hosts_path(),
            owner_uid: owner.0,
            owner_gid: owner.1,
        };
        self.log("info", "starting the tunnel; an approval prompt may ask for permission to change routes");
        if self.jobs.send(Job::Connect { request, control }).is_err() {
            self.running = false;
            self.status = "Error".into();
            self.error = "The background session thread is gone.".into();
        }
    }

    fn disconnect(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.log("info", "disconnect requested; routes will be restored when the tunnel stops");
        self.status = "Disconnected".into();
    }

    fn pump(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                ControlEvent::Log { level, msg } => self.log(&level, msg),
                ControlEvent::Status { status } => {
                    self.status = status_label(&status).into();
                    if status == "connected" {
                        self.connected_at.get_or_insert_with(Instant::now);
                        self.running = true;
                    }
                    if status == "disconnected" || status == "error" {
                        self.connected_at = None;
                        self.rate_up = 0.0;
                        self.rate_down = 0.0;
                    }
                }
                ControlEvent::Stats { up, down } => {
                    let now = Instant::now();
                    if let Some((then, prev_up, prev_down)) = self.last_sample {
                        let secs = now.duration_since(then).as_secs_f64().max(0.001);
                        self.rate_up = (up.saturating_sub(prev_up)) as f64 / secs;
                        self.rate_down = (down.saturating_sub(prev_down)) as f64 / secs;
                    }
                    self.last_sample = Some((now, up, down));
                    self.up = up;
                    self.down = down;
                }
                ControlEvent::PublicIp { phase, value } => {
                    if phase == "before" {
                        self.ip_before = value;
                    } else {
                        self.ip_after = value;
                    }
                }
                ControlEvent::HostKeyPrompt { fingerprint, changed } => {
                    self.pending_prompt = Some(PendingPrompt { fingerprint, changed });
                }
                ControlEvent::Error { message, hint } => {
                    self.error = message;
                    self.hint = hint;
                    self.status = "Error".into();
                }
                ControlEvent::Exit { .. } => {
                    self.running = false;
                    self.repaint = false;
                    if self.status == "Connecting" || self.status == "Reconnecting" {
                        self.status = "Disconnected".into();
                    }
                }
                ControlEvent::Info { transport, server } => {
                    self.transport = transport;
                    self.log("info", format!("forwarding through {server}"));
                }
            }
        }
    }

    fn resolve_prompt(&mut self, choice: HostKeyChoice) {
        self.prompt_slot.resolve(choice);
        self.pending_prompt = None;
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump();
        if self.startup_connect && !self.running {
            self.startup_connect = false;
            self.connect();
        }
        if self.config.start_minimized {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            self.config.start_minimized = false;
        }
        if self.running || self.pending_prompt.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("nav").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(fox_image(36.0));
                ui.label(egui::RichText::new("Fox-VPN").size(22.0).strong().color(FOX_CREAM));
                ui.add_space(8.0);
                if ui.selectable_label(matches!(self.screen, Screen::Main), "Connection").clicked() {
                    self.screen = Screen::Main;
                }
                if ui.selectable_label(matches!(self.screen, Screen::Settings), "Settings").clicked() {
                    self.screen = Screen::Settings;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(foxvpn::version()).color(FOX_MUTED));
                });
            });
        });
        egui::CentralPanel::default().show(ui, |ui| match self.screen {
            Screen::Main => self.main_screen(ui),
            Screen::Settings => self.settings_screen(ui),
        });
        if let Some(prompt) = self.pending_prompt.clone() {
            let mut open = true;
            egui::Window::new("SSH host key").collapsible(false).resizable(false).open(&mut open).show(&ctx, |ui| {
                ui.label(if prompt.changed {
                    "The server key changed. Accept it only if you verified the fingerprint out of band."
                } else {
                    "This server has not been trusted yet. Compare the fingerprint with the host administrator."
                });
                ui.add_space(6.0);
                ui.monospace(&prompt.fingerprint);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if prompt.changed {
                        if ui.button("Replace saved key").clicked() {
                            self.resolve_prompt(HostKeyChoice::Replace);
                        }
                    } else if ui.button("Trust this key").clicked() {
                        self.resolve_prompt(HostKeyChoice::TrustNew);
                    }
                    if ui.button("Reject").clicked() {
                        self.resolve_prompt(HostKeyChoice::Reject);
                    }
                });
            });
            if !open {
                self.resolve_prompt(HostKeyChoice::Reject);
            }
        }
    }
}

impl App {
    fn main_screen(&mut self, ui: &mut egui::Ui) {
        let status = self.status.clone();
        let running = self.running;
        let endpoint = self.config.profiles.get(self.selected).map(|p| format!("{}    {}", p.name, p.endpoint())).unwrap_or_default();
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(fox_image(56.0));
                ui.add_space(10.0);
                let label = if running { "Disconnect" } else { "Connect" };
                let fill = if running { FOX_ORANGE_DEEP } else { FOX_ORANGE };
                let button = egui::Button::new(egui::RichText::new(label).size(20.0).strong().color(FOX_INK))
                    .fill(fill)
                    .min_size(egui::vec2(180.0, 52.0));
                if ui.add(button).clicked() {
                    if running {
                        self.disconnect();
                    } else {
                        self.connect();
                    }
                }
                ui.add_space(16.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Status").size(12.0).color(FOX_MUTED));
                    ui.label(egui::RichText::new(&status).size(22.0).strong().color(status_color(&status)));
                    ui.label(egui::RichText::new(endpoint).color(FOX_CREAM));
                });
            });
        });
        if !self.startup_note.is_empty() {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::from_rgb(240, 180, 70), &self.startup_note);
            if ui.button("Repair leftover routes").clicked() {
                self.repair();
            }
        }
        if !self.error.is_empty() {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::from_rgb(230, 90, 90), &self.error);
            ui.label(&self.hint);
        }
        ui.add_space(8.0);
        ui.separator();
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(egui::vec2(520.0, 0.0), egui::Layout::top_down(egui::Align::LEFT), |ui| {
                self.connection_form(ui);
            });
            ui.vertical(|ui| {
                self.status_panel(ui);
            });
        });
    }

    fn connection_form(&mut self, ui: &mut egui::Ui) {
        field_label(ui, egui::include_image!("../../../assets/icons/ic_user.png"), "Profile");
        self.profile_combo(ui);
        let mut host = String::new();
        let mut port = config::DEFAULT_PORT;
        let mut username = config::DEFAULT_USER.to_string();
        let mut auth = AuthMethod::PrivateKey;
        let mut routing = RoutingMode::FullTunnel;
        let mut auto_networks = false;
        let mut tunnel_dns = true;
        let mut ipv4 = true;
        let mut ipv6 = false;
        let mut reconnect = true;
        let mut verbose = true;
        let mut transport = TransportMode::SshDirect;
        if let Some(profile) = self.config.profiles.get(self.selected) {
            host = profile.host.clone();
            port = profile.port;
            username = profile.username.clone();
            auth = profile.authentication;
            routing = profile.routing_mode;
            auto_networks = profile.auto_networks;
            tunnel_dns = profile.tunnel_dns;
            ipv4 = profile.ipv4;
            ipv6 = profile.ipv6;
            reconnect = profile.reconnect;
            verbose = profile.verbose_logging;
            transport = profile.transport;
        }
        field_label(ui, egui::include_image!("../../../assets/icons/ic_server.png"), "SSH server");
        ui.text_edit_singleline(&mut host);
        ui.horizontal(|ui| {
            ui.add(icon_image(egui::include_image!("../../../assets/icons/ic_route.png")));
            ui.label("Port");
            ui.add(egui::DragValue::new(&mut port).range(1..=65535));
            ui.add(icon_image(egui::include_image!("../../../assets/icons/ic_user.png")));
            ui.label("User");
            ui.text_edit_singleline(&mut username);
        });
        auth_combo(ui, &mut auth);
        if matches!(auth, AuthMethod::PrivateKey | AuthMethod::PrivateKeyPassphrase) {
            field_label(ui, egui::include_image!("../../../assets/icons/ic_key.png"), "Private key file");
            ui.text_edit_singleline(&mut self.key_path_text);
        }
        field_label(ui, egui::include_image!("../../../assets/icons/ic_lock.png"), "Password");
        ui.add(egui::TextEdit::singleline(&mut self.password).password(true).hint_text("used when authentication is password"));
        field_label(ui, egui::include_image!("../../../assets/icons/ic_key.png"), "Key passphrase");
        ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true).hint_text("only for an encrypted key"));
        ui.checkbox(&mut self.remember_secrets, "Remember secrets in the system keyring");
        routing_combo(ui, &mut routing);
        ui.checkbox(&mut auto_networks, "Discover remote networks (auto-nets)");
        ui.checkbox(&mut tunnel_dns, "Send DNS through the tunnel");
        ui.checkbox(&mut ipv4, "IPv4");
        ui.checkbox(&mut ipv6, "IPv6 (requires the full-IP helper; otherwise IPv6 is blocked)");
        ui.checkbox(&mut reconnect, "Reconnect after network loss");
        ui.checkbox(&mut verbose, "Verbose logs");
        transport_combo(ui, &mut transport);
        ui.label(transport.label());
        if let Some(profile) = self.config.profiles.get_mut(self.selected) {
            profile.host = host;
            profile.port = port;
            profile.username = username;
            profile.authentication = auth;
            profile.routing_mode = routing;
            profile.auto_networks = auto_networks;
            profile.tunnel_dns = tunnel_dns;
            profile.ipv4 = ipv4;
            profile.ipv6 = ipv6;
            profile.reconnect = reconnect;
            profile.verbose_logging = verbose;
            profile.transport = transport;
        }
    }

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let duration = duration_text(self.connected_at);
        let down_rate = format_rate(self.rate_down);
        let down_total = format_bytes(self.down);
        let up_rate = format_rate(self.rate_up);
        let up_total = format_bytes(self.up);
        let before = self.ip_before.clone();
        let after = self.ip_after.clone();
        let transport = if self.transport.is_empty() { "—".into() } else { self.transport.clone() };
        card(ui, |ui| {
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_route.png"), "Duration", &duration);
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_down.png"), "Download", &format!("{down_rate}   {down_total}"));
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_up.png"), "Upload", &format!("{up_rate}   {up_total}"));
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_globe.png"), "Public IP before", &before);
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_globe.png"), "Public IP through tunnel", &after);
            stat_row(ui, egui::include_image!("../../../assets/icons/ic_server.png"), "Transport", &transport);
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add(icon_image(egui::include_image!("../../../assets/icons/ic_log.png")));
            ui.label(egui::RichText::new("Activity").strong().color(FOX_CREAM));
            if ui.button("Clear").clicked() {
                self.logs.clear();
            }
        });
        let lines: Vec<String> = self.logs.iter().map(|(level, msg)| format!("[{level}] {msg}")).collect();
        egui::Frame::new().fill(egui::Color32::from_rgb(12, 12, 12)).corner_radius(10).inner_margin(8).show(ui, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).max_height(360.0).show(ui, |ui| {
                for line in lines {
                    ui.monospace(egui::RichText::new(line).color(FOX_MUTED));
                }
            });
        });
    }

    fn settings_screen(&mut self, ui: &mut egui::Ui) {
        ui.label(format!("Configuration file: {}", config::config_path().display()));
        ui.label("Passwords and passphrases are not written into this file.");
        ui.horizontal(|ui| {
            if ui.button("New profile").clicked() {
                self.apply_editors();
                let profile = Profile::blank();
                self.config.active_profile = Some(profile.id.clone());
                self.config.profiles.push(profile);
                self.selected = self.config.profiles.len() - 1;
                self.pull_editors();
            }
            if ui.button("Delete profile").clicked() && !self.config.profiles.is_empty() {
                self.config.profiles.remove(self.selected);
                if self.config.profiles.is_empty() {
                    self.config.profiles.push(Profile::blank());
                }
                self.selected = self.selected.min(self.config.profiles.len() - 1);
                self.pull_editors();
            }
            if ui.button("Save").clicked() {
                match self.save() {
                    Ok(()) => self.log("info", format!("saved {}", config::config_path().display())),
                    Err(err) => {
                        self.error = err;
                    }
                }
            }
            if ui.button("Repair network").clicked() {
                self.repair();
            }
        });
        ui.separator();
        self.profile_combo(ui);
        let mut name = String::new();
        let mut timeout = 20u64;
        let mut keepalive = 15u64;
        let mut mtu = 1500u16;
        let mut exclude_lan = false;
        let mut kill_switch = false;
        if let Some(profile) = self.config.profiles.get(self.selected) {
            name = profile.name.clone();
            timeout = profile.connect_timeout_secs;
            keepalive = profile.keepalive_secs;
            mtu = profile.mtu;
            exclude_lan = profile.exclude_lan;
            kill_switch = profile.kill_switch;
        }
        ui.label("Profile name");
        ui.text_edit_singleline(&mut name);
        ui.horizontal(|ui| {
            ui.label("Timeout (s)");
            ui.add(egui::DragValue::new(&mut timeout).range(1..=120));
            ui.label("Keepalive (s)");
            ui.add(egui::DragValue::new(&mut keepalive).range(0..=300));
            ui.label("MTU");
            ui.add(egui::DragValue::new(&mut mtu).range(1280..=1500));
        });
        ui.checkbox(&mut exclude_lan, "Exclude LAN addresses from the full tunnel");
        ui.checkbox(&mut kill_switch, "Kill switch (drop traffic that is not the tunnel or the SSH server)");
        if let Some(profile) = self.config.profiles.get_mut(self.selected) {
            profile.name = name;
            profile.connect_timeout_secs = timeout;
            profile.keepalive_secs = keepalive;
            profile.mtu = mtu;
            profile.exclude_lan = exclude_lan;
            profile.kill_switch = kill_switch;
        }
        ui.label("DNS servers");
        ui.text_edit_singleline(&mut self.dns_text);
        ui.label("Split-tunnel prefixes, one CIDR per line");
        ui.add(egui::TextEdit::multiline(&mut self.split_text).desired_rows(4));
        ui.label("Remote helper command (empty runs the embedded Python helper)");
        ui.text_edit_singleline(&mut self.remote_command);
        ui.checkbox(&mut self.jump_on, "SSH jump host");
        if self.jump_on {
            ui.horizontal(|ui| {
                ui.label("Host");
                ui.text_edit_singleline(&mut self.jump_host);
                ui.label("Port");
                ui.add(egui::DragValue::new(&mut self.jump_port).range(1..=65535));
                ui.label("User");
                ui.text_edit_singleline(&mut self.jump_user);
            });
            ui.label("Jump host private key");
            ui.text_edit_singleline(&mut self.jump_key);
            ui.label("Jump password");
            ui.add(egui::TextEdit::singleline(&mut self.jump_password).password(true));
            ui.label("Jump key passphrase");
            ui.add(egui::TextEdit::singleline(&mut self.jump_passphrase).password(true));
        }
        ui.checkbox(&mut self.socks_on, "SOCKS proxy for the SSH connection");
        if self.socks_on {
            ui.horizontal(|ui| {
                ui.label("Host");
                ui.text_edit_singleline(&mut self.socks_host);
                ui.label("Port");
                ui.add(egui::DragValue::new(&mut self.socks_port).range(1..=65535));
                ui.label("User");
                ui.text_edit_singleline(&mut self.socks_user);
            });
            ui.label("SOCKS password");
            ui.add(egui::TextEdit::singleline(&mut self.socks_password).password(true));
        }
        ui.separator();
        ui.checkbox(&mut self.config.connect_on_startup, "Connect the active profile when the application starts");
        ui.checkbox(&mut self.config.start_minimized, "Start minimized");
        ui.add(egui::Slider::new(&mut self.config.log_verbosity, 0..=3).text("log verbosity"));
        ui.label("0 warnings, 1 connection events, 2 flows, 3 trace. Per-flow detail also follows the profile's verbose logging switch.");
    }

    fn profile_combo(&mut self, ui: &mut egui::Ui) {
        let names: Vec<String> = self.config.profiles.iter().map(|p| format!("{} ({})", p.name, p.endpoint())).collect();
        let current = names.get(self.selected).cloned().unwrap_or_else(|| "No profile".into());
        let mut chosen = None;
        egui::ComboBox::from_id_salt("profile").selected_text(current).show_ui(ui, |ui| {
            for (index, name) in names.iter().enumerate() {
                if ui.selectable_label(index == self.selected, name).clicked() {
                    chosen = Some(index);
                }
            }
        });
        if let Some(index) = chosen {
            if index != self.selected {
                self.apply_editors();
                self.selected = index;
                if let Some(profile) = self.config.profiles.get(index) {
                    self.config.active_profile = Some(profile.id.clone());
                }
                self.pull_editors();
            }
        }
    }

    fn repair(&mut self) {
        if foxvpn::platform::is_elevated() {
            match foxvpn::platform::repair() {
                Ok(()) => {
                    self.startup_note.clear();
                    self.log("info", "network rollback completed");
                }
                Err(err) => self.log("error", format!("{} {}", err.message(), err.hint())),
            }
            return;
        }
        let cli = foxvpn::worker::cli_path();
        match std::process::Command::new("pkexec").arg(&cli).arg("repair").status() {
            Ok(status) if status.success() => {
                self.startup_note.clear();
                self.log("info", "network rollback completed");
            }
            Ok(status) => self.log("error", format!("repair exited with {status}")),
            Err(err) => self.log("error", format!("could not start repair: {err}")),
        }
    }
}

fn spawn_worker() -> tokio::sync::mpsc::UnboundedSender<Job> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("fox-vpn-session".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
            runtime.block_on(async move {
                while let Some(job) = rx.recv().await {
                    match job {
                        Job::Connect { request, control } => {
                            if let Err(err) = foxvpn::elevate_and_run(request, control.clone()).await {
                                let text = err.message().to_string();
                                if text.contains("privilege") || text.contains("pkexec") || text.contains("worker") || text.contains("root") || text.contains("elevation") {
                                    control.status("error");
                                    let _ = control.events.send(ControlEvent::Error { message: text, hint: err.hint().to_string() });
                                    let _ = control.events.send(ControlEvent::Exit { code: 1 });
                                }
                            }
                        }
                    }
                }
            });
        })
        .expect("session thread");
    tx
}

fn take_or_load(field: &mut String, store: &SystemStore, account: &str, remember: bool, label: &str) -> std::result::Result<Option<Zeroizing<String>>, String> {
    if !field.is_empty() {
        if remember {
            store.set(account, field)?;
        }
        return Ok(Some(Zeroizing::new(std::mem::take(field))));
    }
    match store.get(account) {
        Ok(Some(value)) if !value.is_empty() => Ok(Some(Zeroizing::new(value))),
        Ok(_) => Err(format!("Enter the {label}.")),
        Err(err) => Err(err),
    }
}

fn optional_path(text: &str) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() { None } else { Some(PathBuf::from(text)) }
}

fn auth_combo(ui: &mut egui::Ui, value: &mut AuthMethod) {
    let label = match value {
        AuthMethod::PrivateKey => "Private key",
        AuthMethod::Password => "Password",
        AuthMethod::PrivateKeyPassphrase => "Encrypted private key",
    };
    egui::ComboBox::from_id_salt("auth").selected_text(label).show_ui(ui, |ui| {
        ui.selectable_value(value, AuthMethod::PrivateKey, "Private key");
        ui.selectable_value(value, AuthMethod::Password, "Password");
        ui.selectable_value(value, AuthMethod::PrivateKeyPassphrase, "Encrypted private key");
    });
}

fn routing_combo(ui: &mut egui::Ui, value: &mut RoutingMode) {
    let label = match value {
        RoutingMode::FullTunnel => "Full tunnel (0.0.0.0/0)",
        RoutingMode::SplitTunnel => "Split tunnel",
    };
    egui::ComboBox::from_id_salt("route").selected_text(label).show_ui(ui, |ui| {
        ui.selectable_value(value, RoutingMode::FullTunnel, "Full tunnel (0.0.0.0/0)");
        ui.selectable_value(value, RoutingMode::SplitTunnel, "Split tunnel");
    });
}

fn transport_combo(ui: &mut egui::Ui, value: &mut TransportMode) {
    egui::ComboBox::from_id_salt("transport").selected_text(value.label()).show_ui(ui, |ui| {
        ui.selectable_value(value, TransportMode::SshDirect, TransportMode::SshDirect.label());
        ui.selectable_value(value, TransportMode::HelperL4, TransportMode::HelperL4.label());
        ui.selectable_value(value, TransportMode::HelperL3, TransportMode::HelperL3.label());
    });
}

fn status_label(status: &str) -> &str {
    match status {
        "connecting" => "Connecting",
        "connected" => "Connected",
        "reconnecting" => "Reconnecting",
        "disconnected" => "Disconnected",
        "error" => "Error",
        other => other,
    }
}

const FOX_ORANGE: egui::Color32 = egui::Color32::from_rgb(255, 122, 24);
const FOX_ORANGE_DEEP: egui::Color32 = egui::Color32::from_rgb(196, 90, 16);
const FOX_INK: egui::Color32 = egui::Color32::from_rgb(20, 20, 20);
const FOX_CREAM: egui::Color32 = egui::Color32::from_rgb(242, 242, 242);
const FOX_MUTED: egui::Color32 = egui::Color32::from_rgb(154, 154, 154);

fn fox_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    let cream = FOX_CREAM;
    visuals.window_fill = egui::Color32::from_rgb(16, 16, 16);
    visuals.panel_fill = egui::Color32::from_rgb(16, 16, 16);
    visuals.extreme_bg_color = egui::Color32::from_rgb(12, 12, 12);
    visuals.faint_bg_color = egui::Color32::from_rgb(32, 32, 32);
    visuals.code_bg_color = egui::Color32::from_rgb(12, 12, 12);
    visuals.hyperlink_color = FOX_ORANGE;
    visuals.warn_fg_color = FOX_ORANGE;
    visuals.error_fg_color = egui::Color32::from_rgb(255, 138, 112);
    visuals.selection.bg_fill = egui::Color32::from_rgb(48, 32, 18);
    visuals.selection.stroke.color = FOX_ORANGE;
    let radius = egui::CornerRadius::same(10);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = radius;
        widget.fg_stroke.color = cream;
    }
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(26, 26, 26);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(36, 36, 36);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(48, 48, 48);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(28, 28, 28);
    visuals.widgets.open.bg_fill = egui::Color32::from_rgb(24, 24, 24);
    visuals
}

fn fox_image(size: f32) -> egui::Image<'static> {
    egui::Image::new(egui::include_image!("../../../assets/fox-vpn.png"))
        .fit_to_exact_size(egui::vec2(size, size))
        .corner_radius(egui::CornerRadius::same((size * 0.22) as u8))
}

fn icon_image(source: egui::ImageSource<'static>) -> egui::Image<'static> {
    egui::Image::new(source).fit_to_exact_size(egui::vec2(18.0, 18.0))
}

fn field_label(ui: &mut egui::Ui, source: egui::ImageSource<'static>, text: &str) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add(icon_image(source));
        ui.label(egui::RichText::new(text).color(FOX_CREAM));
    });
}

fn stat_row(ui: &mut egui::Ui, source: egui::ImageSource<'static>, title: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add(icon_image(source));
        ui.label(egui::RichText::new(title).color(FOX_MUTED));
        ui.label(egui::RichText::new(value).color(FOX_CREAM));
    });
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(26, 26, 26))
        .corner_radius(16)
        .inner_margin(12)
        .show(ui, add);
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "Connected" => egui::Color32::from_rgb(141, 220, 120),
        "Connecting" | "Reconnecting" => FOX_ORANGE,
        "Error" => egui::Color32::from_rgb(255, 138, 112),
        _ => FOX_MUTED,
    }
}

fn duration_text(start: Option<Instant>) -> String {
    let Some(start) = start else { return "00:00:00".into() };
    let secs = start.elapsed().as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

fn format_rate(n: f64) -> String {
    format!("{}/s", format_bytes(n as u64))
}
