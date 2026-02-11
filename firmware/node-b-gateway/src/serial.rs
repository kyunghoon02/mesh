use embedded_io::{Read, Write};

// Simple length-prefixed framing over UART/Serial.
// Frame format: [len_lo, len_hi, payload...]
// NOTE: blocking read; non-blocking mode can be added later.

pub struct SerialManager<U> {
    uart: U,
}

#[repr(u8)]
pub enum SerialError {
    Io = 1,
    InvalidLen = 2,
    Empty = 3,
}

impl<U> SerialManager<U>
where
    U: Read + Write,
{
    pub fn new(uart: U) -> Self {
        Self { uart }
    }

    pub fn read_frame_blocking(&mut self, buf: &mut [u8]) -> Result<usize, SerialError> {
        let mut len_bytes = [0u8; 2];
        self.read_exact(&mut len_bytes)?;

        let len = u16::from_le_bytes(len_bytes) as usize;
        if len == 0 {
            return Err(SerialError::Empty);
        }
        if len > buf.len() {
            return Err(SerialError::InvalidLen);
        }

        self.read_exact(&mut buf[..len])?;
        Ok(len)
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<(), SerialError> {
        if payload.len() > u16::MAX as usize {
            return Err(SerialError::InvalidLen);
        }

        let len = payload.len() as u16;
        let len_bytes = len.to_le_bytes();
        self.write_all(&len_bytes)?;
        self.write_all(payload)?;
        Ok(())
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), SerialError> {
        while !buf.is_empty() {
            match self.uart.read(buf) {
                Ok(0) => return Err(SerialError::Io),
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(_) => return Err(SerialError::Io),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), SerialError> {
        while !buf.is_empty() {
            match self.uart.write(buf) {
                Ok(0) => return Err(SerialError::Io),
                Ok(n) => buf = &buf[n..],
                Err(_) => return Err(SerialError::Io),
            }
        }
        Ok(())
    }
}
