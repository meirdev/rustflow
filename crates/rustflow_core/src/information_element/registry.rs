use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use super::{DataType, ElementId, InformationElement, Semantic, iana};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    UnsupportedSemantic {
        id: ElementId,
        data_type: DataType,
        semantic: Semantic,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSemantic {
                id,
                data_type,
                semantic,
            } => write!(
                f,
                "element {id}: {data_type} does not support {semantic} semantics"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

#[derive(Clone)]
pub struct Registry {
    elements: Arc<FxHashMap<ElementId, InformationElement>>,
}

impl Registry {
    pub fn empty() -> Self {
        Self {
            elements: Arc::default(),
        }
    }

    pub fn iana() -> Self {
        let mut registry = Self::empty();
        for &(id, name, data_type, semantics) in iana::ELEMENTS {
            registry
                .insert(InformationElement {
                    id: ElementId::iana(id),
                    name: Cow::Borrowed(name),
                    data_type,
                    semantic: semantics,
                    unit: None,
                    range: None,
                    description: None,
                })
                .expect("IANA elements have valid semantics");
        }
        registry
    }

    pub fn insert(
        &mut self,
        element: InformationElement,
    ) -> Result<Option<InformationElement>, RegistryError> {
        element.check()?;
        Ok(Arc::make_mut(&mut self.elements).insert(element.id, element))
    }

    pub fn get(&self, element: ElementId) -> Option<&InformationElement> {
        self.elements.get(&element)
    }

    pub fn find(&self, name: &str) -> Option<ElementId> {
        self.elements
            .values()
            .find(|element| element.name == name)
            .map(|element| element.id)
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::iana()
    }
}

#[cfg(test)]
mod tests {
    use super::{Registry, iana};

    #[test]
    fn iana_registry_loads_all_elements() {
        let registry = Registry::iana();
        assert_eq!(registry.elements.len(), iana::ELEMENTS.len());
    }
}
