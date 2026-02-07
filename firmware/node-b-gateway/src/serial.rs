use embedded_io::{ErrorKind, Read, Write};

// Simple length-prefixed framing over UART/Serial.
// Frame format: [len_lo, len_hi, payload...]

pub struct SerialManager<U> {
    uart: U,
    len_buf: [u8; 2],
    len_read: usize,
    payload_len: Option<usize>,
    payload_read: usize,
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
        Self {
            uart,
            len_buf: [0u8; 2],
            len_read: 0,
            payload_len: None,
            payload_read: 0,
        }
    }

    /// Non-blocking frame reader. Returns Ok(Some(len)) when a full frame is ready.
    pub fn poll_read_frame(&mut self, buf: &mut [u8]) -> Result<Option<usize>, SerialError> {
        if self.payload_len.is_none() {
            // Read length prefix
            let n = self.read_nonblocking(&mut self.len_buf[self.len_read..])?;
            self.len_read += n;
            if self.len_read < 2 {
                return Ok(None);
            }

            let len = u16::from_le_bytes(self.len_buf) as usize;
            if len == 0 {
                self.reset_rx();
                return Err(SerialError::Empty);
            }
            if len > buf.len() {
                self.reset_rx();
                return Err(SerialError::InvalidLen);
            }

            self.payload_len = Some(len);
            self.payload_read = 0;
        }

        if let Some(len) = self.payload_len {
            let n = self.read_nonblocking(&mut buf[self.payload_read..len])?;
            self.payload_read += n;
            if self.payload_read < len {
                return Ok(None);
            }

            self.reset_rx();
            return Ok(Some(len));
        }

        Ok(None)
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

    fn read_nonblocking(&mut self, buf: &mut [u8]) -> Result<usize, SerialError> {
        match self.uart.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    Ok(0)
                } else {
                    Err(SerialError::Io)
                }
            }
        }
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

    fn reset_rx(&mut self) {
        self.len_read = 0;
        self.payload_len = None;
        self.payload_read = 0;
    }
}
