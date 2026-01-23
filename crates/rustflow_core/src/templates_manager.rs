use rustc_hash::FxHashMap;

use crate::ie_registry::IERegistry;
use crate::types::FieldSpecifier;

pub type Key = (u32, u16);

#[derive(Debug)]
pub struct Template {
    pub fields: Vec<FieldSpecifier>,
}

pub struct TemplatesManager {
    templates: FxHashMap<Key, Template>,
    ie_registry: IERegistry,
}

impl TemplatesManager {
    pub fn new() -> Self {
        TemplatesManager {
            templates: FxHashMap::default(),
            ie_registry: IERegistry::new_with_iana_elements(),
        }
    }

    pub fn with_registry(registry: IERegistry) -> Self {
        TemplatesManager {
            templates: FxHashMap::default(),
            ie_registry: registry,
        }
    }

    pub fn add_template(&mut self, key: Key, fields: Vec<FieldSpecifier>) {
        self.templates.insert(key, Template { fields });
    }

    pub fn remove_template(&mut self, key: Key) -> Option<Template> {
        self.templates.remove(&key)
    }

    pub fn get_template(&self, key: Key) -> Option<&Template> {
        self.templates.get(&key)
    }

    pub fn ie_registry(&self) -> &IERegistry {
        &self.ie_registry
    }

    pub fn clear(&mut self) {
        self.templates.clear();
    }
}

impl Default for TemplatesManager {
    fn default() -> Self {
        Self::new()
    }
}
