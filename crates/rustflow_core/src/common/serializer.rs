use macaddr::MacAddr6;

pub fn serialize_as_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn serialize_mac_as_text<S>(mac: &Option<MacAddr6>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match mac {
        Some(mac) => serializer.serialize_some(&mac.to_string()),
        None => serializer.serialize_none(),
    }
}
