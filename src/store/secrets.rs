use std::collections::HashMap;

use secrecy::SecretString;

#[derive(Clone, Debug)]
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
            backend: "session-memory".to_string(),
            warning: Some(
                "Native keychain integration is disabled in this environment; secrets are stored only for the current session."
                    .to_string(),
            ),
        }
    }
}
