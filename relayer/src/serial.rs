use std::sync::Arc;

use common::{SecurePacket, SerialCommand, SerialFrame, SerialResponse};
use postcard::{from_bytes, to_allocvec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_serial::{DataBits, FlowControl, Parity, SerialPortBuilderExt, SerialStream, StopBits};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct SerialClient {
    inner: Arc<Mutex<SerialStream>>,
}

impl SerialClient {
    pub async fn open(port: &str, baud: u32) -> Result<Self, String> {
        // Windows: COM 포트, macOS/Linux: /dev/tty.*
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

    pub async fn get_status(&self, sequence_id: u32) -> Result<u8, String> {
        // Node B 상태 조회
        info!(sequence_id = sequence_id, "mesh_getStatus 요청 전송");
        let frame = SerialFrame::new(SerialCommand::GetStatus, sequence_id, &[])
            .ok_or("frame build failed")?;
        let resp = self.send_frame(frame).await?;
        if resp.sequence_id != sequence_id {
            return Err(format!(
                "sequence mismatch: req={} resp={}",
                sequence_id, resp.sequence_id
            ));
        }
        if !resp.success {
            return Err(format!("device error: {}", resp.error_code));
        }
        let data = resp.payload_bytes();
        if data.is_empty() {
            warn!("mesh_getStatus payload empty");
            return Err("empty status".to_string());
        }
        Ok(data[0])
    }

    pub async fn send_sign_request(
        &self,
        sequence_id: u32,
        packet: &SecurePacket,
    ) -> Result<SerialResponse, String> {
        info!(
            sequence_id = sequence_id,
            ciphertext_len = packet.ciphertext_len,
            "eth_send/raw sign request 전송"
        );
        let payload = to_allocvec(packet).map_err(|e| e.to_string())?;
        let frame = SerialFrame::new(SerialCommand::SignRequest, sequence_id, &payload)
            .ok_or("frame build failed")?;
        let resp = self.send_frame(frame).await?;
        if resp.sequence_id != sequence_id {
            return Err(format!(
                "sequence mismatch: req={} resp={}",
                sequence_id, resp.sequence_id
            ));
        }
        Ok(resp)
    }

    pub async fn send_frame(&self, frame: SerialFrame) -> Result<SerialResponse, String> {
        let mut guard = self.inner.lock().await;
        // 프레임 형식: [len_lo, len_hi, payload...]
        let bytes = to_allocvec(&frame).map_err(|e| e.to_string())?;
        let len = bytes.len() as u16;

        if let Err(e) = guard.write_all(&len.to_le_bytes()).await {
            error!("serial length write failed: {}", e);
            return Err(e.to_string());
        }

        if let Err(e) = guard.write_all(&bytes).await {
            error!("serial payload write failed: {}", e);
            return Err(e.to_string());
        }

        if let Err(e) = guard.flush().await {
            error!("serial flush failed: {}", e);
            return Err(e.to_string());
        }

        debug!(
            command = ?frame.command,
            payload_len = bytes.len(),
            "serial frame sent"
        );

        let mut len_buf = [0u8; 2];
        if let Err(e) = guard.read_exact(&mut len_buf).await {
            warn!("serial response length read failed: {}", e);
            return Err(e.to_string());
        }

        let resp_len = u16::from_le_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 1024 {
            warn!("invalid response length: {}", resp_len);
            return Err("invalid response length".into());
        }

        let mut resp_buf = vec![0u8; resp_len];
        if let Err(e) = guard.read_exact(&mut resp_buf).await {
            warn!("serial response body read failed: {}", e);
            return Err(e.to_string());
        }

        debug!(len = resp_len, "serial response received");

        match from_bytes::<SerialResponse>(&resp_buf) {
            Ok(resp) => {
                if !resp.success {
                    warn!(
                        error_code = resp.error_code,
                        sequence_id = resp.sequence_id,
                        "serial error response"
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                error!("serial response decode failed: {}", e);
                Err(e.to_string())
            }
        }
    }
}
