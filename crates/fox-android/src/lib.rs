//! JNI entry points for Android. The host build exports a marker so the crate
//! type-checks without the NDK. The real `VpnService` bridge is compiled only
//! when the target OS is Android.

#[cfg(target_os = "android")]
mod android {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    use jni::objects::{GlobalRef, JClass, JString, JValue};
    use jni::sys::{jint, jstring};
    use jni::JNIEnv;

    use foxvpn::config::{self, Profile};
    use foxvpn::control::{ControlEvent, HostKeyChoice, PromptSlot, SessionControl};
    use foxvpn::secrets::SessionSecrets;
    use foxvpn::session::{self, SessionRequest};
    use foxvpn::ssh_link::SocketGuard;

    struct AndroidGuard;
    impl SocketGuard for AndroidGuard {
        fn prepare(&self, raw_fd: i32) -> bool {
            protect_fd(raw_fd)
        }
    }

    fn protect_fd(fd: i32) -> bool {
        call_bool("protectSocket", "(I)Z", &[JValue::Int(fd)])
    }

    fn call_bool(name: &str, sig: &str, args: &[JValue]) -> bool {
        let (Some(vm), Some(class)) = (VM.get(), BRIDGE.get()) else { return false };
        let mut env = match vm.attach_current_thread() {
            Ok(env) => env,
            Err(_) => return false,
        };
        env.call_static_method(class, name, sig, args).ok().and_then(|v| v.z().ok()).unwrap_or(false)
    }

    fn emit(line: &str) {
        let (Some(vm), Some(class)) = (VM.get(), BRIDGE.get()) else { return };
        let Ok(mut env) = vm.attach_current_thread() else { return };
        let Ok(text) = env.new_string(line) else { return };
        let _ = env.call_static_method(class, "onEvent", "(Ljava/lang/String;)V", &[JValue::Object(&text)]);
    }

    static VM: OnceLock<jni::JavaVM> = OnceLock::new();
    static BRIDGE: OnceLock<GlobalRef> = OnceLock::new();
    static PROMPT: OnceLock<PromptSlot> = OnceLock::new();
    static CANCEL: AtomicBool = AtomicBool::new(false);

    #[no_mangle]
    pub extern "system" fn Java_dev_muerfox_foxvpn_NativeBridge_start<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        fd: jint,
        config_json: JString<'local>,
    ) -> jstring {
        CANCEL.store(false, Ordering::Relaxed);
        if let Ok(vm) = env.get_java_vm() {
            let _ = VM.set(vm);
        }
        if let Ok(class) = env.find_class("dev/muerfox/foxvpn/NativeBridge") {
            if let Ok(global) = env.new_global_ref(class) {
                let _ = BRIDGE.set(global);
            }
        }
        let json: String = env.get_string(&config_json).map(|s| s.into()).unwrap_or_default();
        let result = std::panic::catch_unwind(|| run_blocking(fd, &json));
        let message = match result {
            Ok(Ok(())) => String::new(),
            Ok(Err(err)) => format!("{} {}", err.message(), err.hint()),
            Err(_) => "native tunnel panicked".into(),
        };
        env.new_string(message).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
    }

    #[no_mangle]
    pub extern "system" fn Java_dev_muerfox_foxvpn_NativeBridge_stop<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) {
        CANCEL.store(true, Ordering::Relaxed);
    }

    #[no_mangle]
    pub extern "system" fn Java_dev_muerfox_foxvpn_NativeBridge_decide<'local>(_env: JNIEnv<'local>, _class: JClass<'local>, choice: jint) {
        let mapped = match choice {
            1 => HostKeyChoice::TrustNew,
            2 => HostKeyChoice::Replace,
            _ => HostKeyChoice::Reject,
        };
        if let Some(slot) = PROMPT.get() {
            slot.resolve(mapped);
        }
    }

    fn run_blocking(fd: i32, json: &str) -> foxvpn::Result<()> {
        let profile: Profile = serde_json::from_str(json).map_err(|e| foxvpn::Error::fatal(e.to_string(), "The Android profile JSON was rejected."))?;
        config::validate_profile(&profile).map_err(|e| foxvpn::Error::fatal(e, "Correct the profile fields."))?;
        let value: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
        let mut secrets = SessionSecrets::default();
        if let Some(password) = value.get("password").and_then(|v| v.as_str()) {
            secrets.password = Some(zeroize::Zeroizing::new(password.to_string()));
        }
        if let Some(passphrase) = value.get("passphrase").and_then(|v| v.as_str()) {
            secrets.passphrase = Some(zeroize::Zeroizing::new(passphrase.to_string()));
        }
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| foxvpn::Error::fatal(e.to_string(), "Could not start the tunnel runtime."))?;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ControlEvent>();
        let prompt = PROMPT.get_or_init(PromptSlot::default).clone();
        let control = SessionControl::new(tx, prompt, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));
        // The static cancel flag is polled by wrapping the control flag.
        let cancel = control.cancel.clone();
        runtime.spawn(async move {
            loop {
                if CANCEL.load(Ordering::Relaxed) {
                    cancel.store(true, Ordering::Relaxed);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });
        let request = SessionRequest {
            profile,
            secrets,
            accept_new_host_key: value.get("accept_new_host_key").and_then(|v| v.as_bool()).unwrap_or(false),
            known_hosts: value.get("known_hosts").and_then(|v| v.as_str()).map(std::path::PathBuf::from).unwrap_or_else(config::known_hosts_path),
            owner: None,
            guard: std::sync::Arc::new(AndroidGuard),
            android_fd: Some(fd),
        };
        runtime.spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Ok(line) = serde_json::to_string(&event) {
                    emit(&line);
                }
            }
        });
        runtime.block_on(session::run_session(request, control))
    }
}

#[cfg(not(target_os = "android"))]
#[no_mangle]
pub extern "C" fn fox_vpn_host_build_marker() -> i32 {
    1
}
