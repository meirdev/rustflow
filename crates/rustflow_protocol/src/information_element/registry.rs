use std::borrow::Cow;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use super::{ElementId, InformationElement, iana};

/// Information elements by enterprise number and ID. Clones share the
/// elements until one of them is changed.
#[derive(Debug, Clone)]
pub struct Registry {
    elements: Arc<FxHashMap<ElementId, InformationElement>>,
}

impl Registry {
    pub fn empty() -> Self {
        Self {
            elements: Arc::default(),
        }
    }

    /// The elements of IANA's IPFIX Information Elements registry.
    pub fn iana() -> Self {
        let mut registry = Self::empty();
        for &(id, name, data_type, semantics) in iana::ELEMENTS {
            registry.insert(InformationElement {
                id,
                enterprise_number: None,
                name: Cow::Borrowed(name),
                data_type,
                semantics,
            });
        }
        registry
    }

    /// Adds an element, replacing any with the same enterprise number and
    /// ID.
    pub fn insert(&mut self, element: InformationElement) {
        Arc::make_mut(&mut self.elements).insert(element.element_id(), element);
    }

    pub fn get(&self, element: ElementId) -> Option<&InformationElement> {
        self.elements.get(&element)
    }

    /// The element named `name`, for looking up values by a name given at
    /// run time; names in code are better as [`iana`](super::iana)
    /// constants.
    pub fn find(&self, name: &str) -> Option<ElementId> {
        // Names are looked up rarely, so a scan saves keeping an index.
        self.elements
            .values()
            .find(|element| element.name == name)
            .map(InformationElement::element_id)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::iana()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::information_element::{DataType, DataTypeSemantics};

    fn element(id: u16, enterprise_number: Option<u32>, name: &'static str) -> InformationElement {
        InformationElement {
            id,
            enterprise_number,
            name: Cow::Borrowed(name),
            data_type: DataType::Unsigned32,
            semantics: Some(DataTypeSemantics::Quantity),
        }
    }

    #[test]
    fn iana_elements_carry_their_data_type_and_semantics() {
        let iana = Registry::iana();
        assert_eq!(
            iana.get(ElementId::iana(1)),
            Some(&InformationElement {
                id: 1,
                enterprise_number: None,
                name: Cow::Borrowed("octetDeltaCount"),
                data_type: DataType::Unsigned64,
                semantics: Some(DataTypeSemantics::DeltaCounter),
            })
        );
        let semantics = |id| iana.get(ElementId::iana(id)).unwrap().semantics;
        assert_eq!(semantics(6), Some(DataTypeSemantics::Flags));
        assert_eq!(semantics(85), Some(DataTypeSemantics::TotalCounter));
        assert_eq!(semantics(291), Some(DataTypeSemantics::List));
        assert_eq!(semantics(36), None);
        assert_eq!(
            iana.get(ElementId::iana(291)).unwrap().data_type,
            DataType::BasicList
        );
    }

    #[test]
    fn deprecated_elements_are_kept_and_unassigned_ids_are_not() {
        let iana = Registry::iana();
        assert_eq!(
            iana.get(ElementId::iana(34)).unwrap().name,
            "samplingInterval"
        );
        assert_eq!(iana.get(ElementId::iana(0)), None);
        assert_eq!(iana.get(ElementId::iana(416)), None);
        assert_eq!(iana.get(ElementId::iana(32767)), None);
    }

    #[test]
    fn enterprise_elements_are_kept_apart_from_iana_ones() {
        let mut registry = Registry::iana();
        registry.insert(element(1, Some(9), "vendorCounter"));
        assert_eq!(
            registry.get(ElementId::from((9, 1))).unwrap().name,
            "vendorCounter"
        );
        assert_eq!(
            registry.get(ElementId::iana(1)).unwrap().name,
            "octetDeltaCount"
        );
        assert_eq!(registry.get(ElementId::from((10, 1))), None);
    }

    #[test]
    fn an_inserted_element_replaces_one_with_the_same_id() {
        let mut registry = Registry::empty();
        registry.insert(element(1000, None, "first"));
        registry.insert(element(1000, None, "second"));
        assert_eq!(registry.get(ElementId::iana(1000)).unwrap().name, "second");
    }

    #[test]
    fn clones_share_the_elements_until_one_is_changed() {
        let iana = Registry::iana();
        let mut clone = iana.clone();
        assert!(Arc::ptr_eq(&iana.elements, &clone.elements));
        clone.insert(element(1000, None, "added"));
        assert!(!Arc::ptr_eq(&iana.elements, &clone.elements));
        assert_eq!(iana.get(ElementId::iana(1000)), None);
    }

    #[test]
    fn elements_are_found_by_name() {
        let mut registry = Registry::iana();
        assert_eq!(
            registry.find("sourceIPv4Address"),
            Some(iana::SOURCE_IPV4_ADDRESS)
        );
        assert_eq!(registry.find("noSuchElement"), None);
        registry.insert(element(1, Some(9), "vendorCounter"));
        assert_eq!(
            registry.find("vendorCounter"),
            Some(ElementId::from((9, 1)))
        );
    }
}
