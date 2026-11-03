//! Borrowed structural scanning before schema-specific allocations. This
//! shares the decoder's head, length and depth checks; the normal decoder
//! still checks map order, key uniqueness and canonical nested objects.

use super::{nested, Decoder, Mode};
use crate::base::Error;

pub(crate) struct Reader<'a>(Decoder<'a>);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(Decoder {
            input: bytes,
            pos: 0,
            mode: Mode::Strict,
        })
    }

    pub(crate) fn head(&mut self) -> Result<(u8, u64), Error> {
        self.0.head()
    }

    pub(crate) fn expect(&mut self, major: u8, n: u64) -> Result<(), Error> {
        if self.head()? == (major, n) {
            Ok(())
        } else {
            Err(Error::ControlRecordMalformed)
        }
    }

    pub(crate) fn bytes(&mut self, major: u8) -> Result<&'a [u8], Error> {
        let (kind, n) = self.head()?;
        if kind != major {
            return Err(Error::ControlRecordMalformed);
        }
        let len = self.0.length(n, 1)?;
        self.0.take(len)
    }

    pub(crate) fn value_bytes(&mut self) -> Result<&'a [u8], Error> {
        let start = self.0.pos;
        self.skip(0)?;
        Ok(&self.0.input[start..self.0.pos])
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.0.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::CborTrailingBytes)
        }
    }

    fn skip(&mut self, depth: usize) -> Result<(), Error> {
        let (major, n) = self.head()?;
        match major {
            2 | 3 => {
                let len = self.0.length(n, 1)?;
                self.0.take(len)?;
            }
            4 | 5 => {
                let depth = nested(depth)?;
                let count = self.0.length(n, if major == 5 { 2 } else { 1 })?;
                for _ in 0..count {
                    self.skip(depth)?;
                    if major == 5 {
                        self.skip(depth)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
