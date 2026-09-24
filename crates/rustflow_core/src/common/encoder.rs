use bytes::BufMut;

/// Serialize a protocol structure into its wire format.
pub trait Encode {
    fn encode<B: BufMut>(&self, buf: &mut B);
}
