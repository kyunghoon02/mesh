use embedded_io::Write;
use esp_hal::{Blocking, usb_serial_jtag::UsbSerialJtag};

// USB Serial/JTAG framed transport:
// [len_lo, len_hi, postcard payload...]
pub struct SerialManager<'d> {
    usb: UsbSerialJtag<'d, Blocking>,
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

impl<'d> SerialManager<'d> {
    pub fn new(usb: UsbSerialJtag<'d, Blocking>) -> Self {
        Self {
            usb,
            len_buf: [0u8; 2],
            len_read: 0,
            payload_len: None,
            payload_read: 0,
        }
    }

    /// Buffer bytes until a complete framed payload is available.
    pub fn poll_read_frame(&mut self, buf: &mut [u8]) -> Result<Option<usize>, SerialError> {
        if self.payload_len.is_none() {
            self.len_read += Self::read_nonblocking(&mut self.usb, &mut self.len_buf[self.len_read..])?;
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
            self.payload_read += Self::read_nonblocking(&mut self.usb, &mut buf[self.payload_read..len])?;
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
        self.write_all(&len.to_le_bytes())?;
        self.write_all(payload)?;
        Ok(())
    }

    fn read_nonblocking(
        usb: &mut UsbSerialJtag<'d, Blocking>,
        buf: &mut [u8],
    ) -> Result<usize, SerialError> {
        let mut count = 0;
        while count < buf.len() {
            match usb.read_byte() {
                Ok(byte) => {
                    buf[count] = byte;
                    count += 1;
                }
                Err(_) => break,
            }
        }

        Ok(count)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), SerialError> {
        while !buf.is_empty() {
            match embedded_io::Write::write(&mut self.usb, buf) {
                Ok(0) => return Err(SerialError::Io),
                Ok(n) => buf = &buf[n..],
                Err(_) => return Err(SerialError::Io),
            }
        }

        self.usb.flush().map_err(|_| SerialError::Io)
    }

    fn reset_rx(&mut self) {
        self.len_read = 0;
        self.payload_len = None;
        self.payload_read = 0;
    }
}
