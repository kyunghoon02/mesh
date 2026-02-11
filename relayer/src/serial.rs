use std::sync::Arc;

use common::{SerialCommand, SerialFrame, SerialResponse, SecurePacket};
use postcard::{from_bytes, to_allocvec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilderExt, SerialStream, StopBits};

#[derive(Clone)]
pub struct SerialClient {
    inner: Arc<Mutex<SerialStream>>,
}

impl SerialClient {
    pub async fn open(port: &str, baud: u32) -> Result<Self, String> {
        // Windows는 COM 포트(예: COM5), macOS/Linux는 /dev/tty.*
        let builder = tokio_serial::new(port, baud)
            .data_bits(DataBits::Eight)
            .stop_bits(StopBits::One)
            .parity(Parity::None)
            .flow_control(FlowControl::None);

        let stream = builder.open_native_async().map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    pub async fn get_status(&self) -> Result<u8, String> {
        // Node B 상태 조회 (0=미페어링, 1=페어링, 2=준비)
        let frame = SerialFrame::new(SerialCommand::GetStatus, 1, &[])
            .ok_or("frame build failed")?;
        let resp = self.send_frame(frame).await?;
        if !resp.success {
            return Err(format!("device error: {}", resp.error_code));
        }
        let data = resp.payload_bytes();
        if data.is_empty() {
            return Err("empty status".to_string());
        }
        Ok(data[0])
    }

    pub async fn send_sign_request(
        &self,
        sequence_id: u32,
        packet: &SecurePacket,
    ) -> Result<SerialResponse, String> {
        let payload = to_allocvec(packet).map_err(|e| e.to_string())?;
        let frame = SerialFrame::new(SerialCommand::SignRequest, sequence_id, &payload)
            .ok_or("frame build failed")?;
        self.send_frame(frame).await
    }

    pub async fn send_frame(&self, frame: SerialFrame) -> Result<SerialResponse, String> {
        let mut guard = self.inner.lock().await;
        // 길이 프리픽스 프레임: [len_lo, len_hi, 페이로드...]
        let bytes = to_allocvec(&frame).map_err(|e| e.to_string())?;
        let len = bytes.len() as u16;

        guard.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        guard.write_all(&bytes).await.map_err(|e| e.to_string())?;
        guard.flush().await.map_err(|e| e.to_string())?;

        let mut len_buf = [0u8; 2];
        guard.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let resp_len = u16::from_le_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 1024 {
            return Err("invalid response length".into());
        }

        let mut resp_buf = vec![0u8; resp_len];
        guard.read_exact(&mut resp_buf).await.map_err(|e| e.to_string())?;
        from_bytes::<SerialResponse>(&resp_buf).map_err(|e| e.to_string())
    }
}
