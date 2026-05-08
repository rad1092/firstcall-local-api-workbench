#[cfg(any(feature = "native-keyring", test))]
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(any(feature = "native-keyring", test))]
use std::fmt::Write as _;

#[cfg(feature = "native-keyring")]
use secrecy::ExposeSecret;
use secrecy::SecretString;
#[cfg(any(feature = "native-keyring", test))]
use sha2::{Digest, Sha256};

const MEMORY_BACKEND: &str = "session-memory";
#[cfg(any(feature = "native-keyring", test))]
const NATIVE_BACKEND: &str = "native-keyring";
#[cfg(feature = "native-keyring")]
const NATIVE_KEYRING_SERVICE: &str = "dev.rad1092.firstcall";
const MEMORY_WARNING: &str = "Native keychain integration is unavailable on this machine or was not enabled; secrets are stored only for the current session.";
#[cfg(any(feature = "native-keyring", test))]
const NATIVE_FALLBACK_WARNING: &str =
    "Native keyring is unavailable; secrets are stored only for the current session.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretStoreStatus {
    pub backend: String,
    pub warning: Option<String>,
}

pub trait SecretStore {
    fn set(&mut self, key: &str, value: SecretString);
    fn get(&self, key: &str) -> Option<SecretString>;
    fn clear(&mut self, key: &str);
    fn status(&self) -> SecretStoreStatus;
}

pub fn default_secret_store() -> Box<dyn SecretStore> {
    build_native_secret_store().unwrap_or_else(|| Box::new(MemorySecretStore::default()))
}

#[derive(Default)]
pub struct MemorySecretStore {
    values: HashMap<String, SecretString>,
}

impl SecretStore for MemorySecretStore {
    fn set(&mut self, key: &str, value: SecretString) {
        self.values.insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<SecretString> {
        self.values.get(key).cloned()
    }

    fn clear(&mut self, key: &str) {
        self.values.remove(key);
    }

    fn status(&self) -> SecretStoreStatus {
        SecretStoreStatus {
            backend: MEMORY_BACKEND.to_string(),
            warning: Some(MEMORY_WARNING.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(feature = "native-keyring", test))]
enum NativeSecretError {
    Unavailable,
}

#[cfg(any(feature = "native-keyring", test))]
trait NativeSecretBackend {
    fn set(&self, account: &str, value: &SecretString) -> Result<(), NativeSecretError>;
    fn get(&self, account: &str) -> Result<Option<SecretString>, NativeSecretError>;
    fn clear(&self, account: &str) -> Result<(), NativeSecretError>;
}

#[cfg(any(feature = "native-keyring", test))]
struct NativeKeyringSecretStore<B> {
    backend: B,
    fallback: MemorySecretStore,
    fallback_active: Cell<bool>,
}

#[cfg(any(feature = "native-keyring", test))]
impl<B: NativeSecretBackend> NativeKeyringSecretStore<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            fallback: MemorySecretStore::default(),
            fallback_active: Cell::new(false),
        }
    }

    fn mark_fallback_active(&self) {
        self.fallback_active.set(true);
    }
}

#[cfg(any(feature = "native-keyring", test))]
impl<B: NativeSecretBackend> SecretStore for NativeKeyringSecretStore<B> {
    fn set(&mut self, key: &str, value: SecretString) {
        let account = keyring_account_for_key(key);
        self.fallback.set(key, value.clone());
        if self.backend.set(&account, &value).is_err() {
            self.mark_fallback_active();
        }
    }

    fn get(&self, key: &str) -> Option<SecretString> {
        let account = keyring_account_for_key(key);
        match self.backend.get(&account) {
            Ok(Some(value)) => Some(value),
            Ok(None) => self.fallback.get(key),
            Err(_) => {
                self.mark_fallback_active();
                self.fallback.get(key)
            }
        }
    }

    fn clear(&mut self, key: &str) {
        let account = keyring_account_for_key(key);
        if self.backend.clear(&account).is_err() {
            self.mark_fallback_active();
        }
        self.fallback.clear(key);
    }

    fn status(&self) -> SecretStoreStatus {
        if self.fallback_active.get() {
            SecretStoreStatus {
                backend: MEMORY_BACKEND.to_string(),
                warning: Some(NATIVE_FALLBACK_WARNING.to_string()),
            }
        } else {
            SecretStoreStatus {
                backend: NATIVE_BACKEND.to_string(),
                warning: None,
            }
        }
    }
}

#[cfg(any(feature = "native-keyring", test))]
fn native_secret_store_from_backend_result<B>(
    backend: Result<B, NativeSecretError>,
) -> Box<dyn SecretStore>
where
    B: NativeSecretBackend + 'static,
{
    match backend {
        Ok(backend) => Box::new(NativeKeyringSecretStore::new(backend)),
        Err(_) => Box::new(MemorySecretStore::default()),
    }
}

#[cfg(feature = "native-keyring")]
#[derive(Clone, Copy, Debug, Default)]
struct SystemKeyringBackend;

#[cfg(feature = "native-keyring")]
impl SystemKeyringBackend {
    fn is_constructible() -> bool {
        let probe_account = keyring_account_for_key("__firstcall_keyring_probe__");
        keyring::Entry::new(NATIVE_KEYRING_SERVICE, &probe_account).is_ok()
    }
}

#[cfg(feature = "native-keyring")]
impl NativeSecretBackend for SystemKeyringBackend {
    fn set(&self, account: &str, value: &SecretString) -> Result<(), NativeSecretError> {
        let entry = keyring::Entry::new(NATIVE_KEYRING_SERVICE, account)
            .map_err(|_| NativeSecretError::Unavailable)?;
        entry
            .set_password(value.expose_secret())
            .map_err(|_| NativeSecretError::Unavailable)
    }

    fn get(&self, account: &str) -> Result<Option<SecretString>, NativeSecretError> {
        let entry = keyring::Entry::new(NATIVE_KEYRING_SERVICE, account)
            .map_err(|_| NativeSecretError::Unavailable)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(SecretString::new(value.into()))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(NativeSecretError::Unavailable),
        }
    }

    fn clear(&self, account: &str) -> Result<(), NativeSecretError> {
        let entry = keyring::Entry::new(NATIVE_KEYRING_SERVICE, account)
            .map_err(|_| NativeSecretError::Unavailable)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(NativeSecretError::Unavailable),
        }
    }
}

#[cfg(feature = "native-keyring")]
fn build_native_secret_store() -> Option<Box<dyn SecretStore>> {
    if SystemKeyringBackend::is_constructible() {
        Some(native_secret_store_from_backend_result(Ok(
            SystemKeyringBackend,
        )))
    } else {
        None
    }
}

#[cfg(not(feature = "native-keyring"))]
fn build_native_secret_store() -> Option<Box<dyn SecretStore>> {
    None
}

#[cfg(any(feature = "native-keyring", test))]
fn keyring_account_for_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"firstcall-secret-key-v1");
    hasher.update([0]);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut suffix, "{byte:02x}").expect("write to string");
    }
    format!("slot-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    const KEYRING_SECRET: &str = "keyring_secret_should_not_leak";
    const KEYRING_BEARER_SECRET: &str = "keyring_bearer_secret_should_not_leak";
    const KEYRING_API_KEY_SECRET: &str = "keyring_api_key_secret_should_not_leak";
    const KEYRING_PASSWORD_SECRET: &str = "keyring_password_secret_should_not_leak";

    #[test]
    fn memory_secret_store_behavior_remains_session_memory() {
        let mut store = MemorySecretStore::default();
        store.set("bearer_token", SecretString::new(KEYRING_SECRET.into()));

        let value = store.get("bearer_token").expect("stored secret");
        assert_eq!(value.expose_secret(), KEYRING_SECRET);

        let status = store.status();
        assert_eq!(status.backend, MEMORY_BACKEND);
        assert_eq!(status.warning.as_deref(), Some(MEMORY_WARNING));

        store.clear("bearer_token");
        assert!(store.get("bearer_token").is_none());
    }

    #[test]
    fn native_keyring_store_round_trips_through_trait_with_fake_backend() {
        let backend = FakeNativeBackend::default();
        let native_values = backend.values.clone();
        let mut store: Box<dyn SecretStore> =
            Box::new(NativeKeyringSecretStore::new(backend.clone()));

        store.set(
            "bearer_token",
            SecretString::new(KEYRING_BEARER_SECRET.into()),
        );
        let value = store.get("bearer_token").expect("stored native secret");
        assert_eq!(value.expose_secret(), KEYRING_BEARER_SECRET);

        let account = keyring_account_for_key("bearer_token");
        assert_eq!(
            native_values.borrow().get(&account).map(String::as_str),
            Some(KEYRING_BEARER_SECRET)
        );

        store.clear("bearer_token");
        assert!(store.get("bearer_token").is_none());
        assert!(!native_values.borrow().contains_key(&account));
    }

    #[test]
    fn native_keyring_status_reports_native_when_backend_is_available() {
        let store = NativeKeyringSecretStore::new(FakeNativeBackend::default());

        assert_eq!(
            store.status(),
            SecretStoreStatus {
                backend: NATIVE_BACKEND.to_string(),
                warning: None,
            }
        );
    }

    #[test]
    fn native_keyring_init_failure_uses_session_memory_status() {
        let store = native_secret_store_from_backend_result::<FakeNativeBackend>(Err(
            NativeSecretError::Unavailable,
        ));

        let status = store.status();
        assert_eq!(status.backend, MEMORY_BACKEND);
        assert_eq!(status.warning.as_deref(), Some(MEMORY_WARNING));
    }

    #[test]
    fn native_keyring_failures_fall_back_to_session_memory_with_safe_warning() {
        let backend = FakeNativeBackend::default();
        backend.fail_set.set(true);
        backend.fail_get.set(true);
        backend.fail_clear.set(true);
        let mut store = NativeKeyringSecretStore::new(backend);

        store.set("api_key", SecretString::new(KEYRING_API_KEY_SECRET.into()));
        let value = store
            .get("api_key")
            .expect("fallback should preserve current session secret");
        assert_eq!(value.expose_secret(), KEYRING_API_KEY_SECRET);
        store.clear("api_key");

        let status = store.status();
        assert_eq!(status.backend, MEMORY_BACKEND);
        assert_eq!(status.warning.as_deref(), Some(NATIVE_FALLBACK_WARNING));
        let status_text = format!("{status:?}");
        for canary in keyring_canaries() {
            assert!(!status_text.contains(canary), "status leaked {canary}");
        }
    }

    #[test]
    fn keyring_account_names_are_deterministic_and_do_not_include_user_text() {
        let key = "https://api.example.com/users?token=keyring_password_secret_should_not_leak";
        let first = keyring_account_for_key(key);
        let second = keyring_account_for_key(key);

        assert_eq!(first, second);
        assert!(first.starts_with("slot-"));
        assert!(!first.contains("https"));
        assert!(!first.contains("api.example.com"));
        assert!(!first.contains(KEYRING_PASSWORD_SECRET));
        assert_ne!(first, keyring_account_for_key("different"));
    }

    #[test]
    fn fake_native_store_serialized_statuses_do_not_expose_secret_canaries() {
        let backend = FakeNativeBackend::default();
        backend.fail_set.set(true);
        let mut store = NativeKeyringSecretStore::new(backend);
        store.set(
            "password",
            SecretString::new(KEYRING_PASSWORD_SECRET.into()),
        );

        let debug_text = format!("{:?}", store.status());
        for canary in keyring_canaries() {
            assert!(!debug_text.contains(canary), "status leaked {canary}");
        }
    }

    #[cfg(not(feature = "native-keyring"))]
    #[test]
    fn default_secret_store_uses_memory_when_native_feature_is_disabled() {
        let store = default_secret_store();
        assert_eq!(store.status().backend, MEMORY_BACKEND);
    }

    #[derive(Clone, Default)]
    struct FakeNativeBackend {
        values: Rc<RefCell<HashMap<String, String>>>,
        fail_set: Rc<Cell<bool>>,
        fail_get: Rc<Cell<bool>>,
        fail_clear: Rc<Cell<bool>>,
    }

    impl NativeSecretBackend for FakeNativeBackend {
        fn set(&self, account: &str, value: &SecretString) -> Result<(), NativeSecretError> {
            if self.fail_set.get() {
                return Err(NativeSecretError::Unavailable);
            }
            self.values
                .borrow_mut()
                .insert(account.to_string(), value.expose_secret().to_string());
            Ok(())
        }

        fn get(&self, account: &str) -> Result<Option<SecretString>, NativeSecretError> {
            if self.fail_get.get() {
                return Err(NativeSecretError::Unavailable);
            }
            Ok(self
                .values
                .borrow()
                .get(account)
                .map(|value| SecretString::new(value.clone().into())))
        }

        fn clear(&self, account: &str) -> Result<(), NativeSecretError> {
            if self.fail_clear.get() {
                return Err(NativeSecretError::Unavailable);
            }
            self.values.borrow_mut().remove(account);
            Ok(())
        }
    }

    fn keyring_canaries() -> [&'static str; 4] {
        [
            KEYRING_SECRET,
            KEYRING_BEARER_SECRET,
            KEYRING_API_KEY_SECRET,
            KEYRING_PASSWORD_SECRET,
        ]
    }
}
