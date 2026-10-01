use bytes::BufMut;

pub trait Encode {
    fn encode<B: BufMut>(&self, buf: &mut B);
}
