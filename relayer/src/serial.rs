use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{PacketType, SecurePacket, SerialCommand, SerialFrame, SerialResponse};
use postcard::{from_bytes, to_allocvec};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use tokio::task::spawn_blocking;
use tracing::{debug, error, info, warn};

type SharedSerial = Arc<Mutex<Box<dyn SerialPort + Send>>>;

const STANDARD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
const SIGN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(65);
const RESPONSE_MIN_LENGTH: usize = 248;
const RESPONSE_MAX_LENGTH: usize = 250;

#[derive(Clone)]
pub struct SerialClient {
    inner: SharedSerial,
}

impl SerialClient {
    pub async fn open(port: &str, baud: u32) -> Result<Self, String> {
        let stream = serialport::new(port, baud)
            .data_bits(DataBits::Eight)
            .stop_bits(StopBits::One)
            .parity(Parity::None)
            .flow_control(FlowControl::None)
            .timeout(STANDARD_RESPONSE_TIMEOUT)
            .open()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            inner: Arc::new(Mutex::new(stream)),
        })
    }

    pub async fn get_status(&self, sequence_id: u32) -> Result<u8, String> {
        info!(
            sequence_id = sequence_id,
            event = "serial.get_status.request",
            "Node-B -> Node A 상태 조회 요청 시작"
        );

        let frame = SerialFrame::new(SerialCommand::GetStatus, sequence_id, &[])
            .ok_or("frame build failed")?;
        let resp = self.send_frame(frame).await?;

        if resp.sequence_id != sequence_id {
            warn!(
                event = "serial.seq_mismatch",
                request_seq = sequence_id,
                response_seq = resp.sequence_id,
                "요청/응답 시퀀스 불일치"
            );
            return Err(format!(
                "sequence mismatch: req={} resp={}",
                sequence_id, resp.sequence_id
            ));
        }
        if !resp.success {
            warn!(
                event = "serial.device_error",
                sequence_id = sequence_id,
                error_code = resp.error_code,
                "기기 응답 실패"
            );
            return Err(format!("device error: {}", resp.error_code));
        }

        let data = resp.payload_bytes();
        if data.is_empty() {
            warn!(
                event = "serial.empty_status",
                sequence_id = sequence_id,
                "상태 응답 페이로드가 비어 있음"
            );
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
            event = "serial.send_sign_request",
            "서명 요청 전송 시작"
        );

        let payload = to_allocvec(packet).map_err(|e| e.to_string())?;
        let frame = SerialFrame::new(SerialCommand::SignRequest, sequence_id, &payload)
            .ok_or("frame build failed")?;
        let inner = self.inner.clone();

        spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| "serial mutex poisoned".to_string())?;

            Self::write_frame_locked(&mut **guard, &frame)?;
            let ack = Self::read_response_locked(
                &mut **guard,
                frame.sequence_id,
                STANDARD_RESPONSE_TIMEOUT,
            )?;

            if ack.sequence_id != sequence_id {
                warn!(
                    event = "serial.seq_mismatch",
                    request_seq = sequence_id,
                    response_seq = ack.sequence_id,
                    "요청/응답 시퀀스 불일치"
                );
                return Err(format!(
                    "sequence mismatch: req={} resp={}",
                    sequence_id, ack.sequence_id
                ));
            }

            if !ack.success || Self::is_final_sign_response(&ack) {
                return Ok(ack);
            }

            info!(
                event = "serial.sign_request_forwarded",
                sequence_id = sequence_id,
                "hardware prompt acknowledged; waiting for final sign response"
            );

            let final_response =
                Self::read_response_locked(&mut **guard, frame.sequence_id, SIGN_RESPONSE_TIMEOUT)?;

            if final_response.sequence_id != sequence_id {
                warn!(
                    event = "serial.seq_mismatch",
                    request_seq = sequence_id,
                    response_seq = final_response.sequence_id,
                    "최종 응답 시퀀스 불일치"
                );
                return Err(format!(
                    "sequence mismatch: req={} resp={}",
                    sequence_id, final_response.sequence_id
                ));
            }

            Ok(final_response)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn send_frame(&self, frame: SerialFrame) -> Result<SerialResponse, String> {
        let inner = self.inner.clone();

        spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| "serial mutex poisoned".to_string())?;
            Self::write_frame_locked(&mut **guard, &frame)?;
            Self::read_response_locked(&mut **guard, frame.sequence_id, STANDARD_RESPONSE_TIMEOUT)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn write_frame_locked(port: &mut dyn SerialPort, frame: &SerialFrame) -> Result<(), String> {
        let bytes = to_allocvec(frame).map_err(|e| e.to_string())?;
        let len = bytes.len() as u16;

        if let Err(e) = port.write_all(&len.to_le_bytes()) {
            error!(
                event = "serial.write_length_failed",
                frame_len = bytes.len(),
                "serial length write failed: {}",
                e
            );
            return Err(e.to_string());
        }

        if let Err(e) = port.write_all(&bytes) {
            error!(
                event = "serial.write_payload_failed",
                frame_len = bytes.len(),
                "serial payload write failed: {}",
                e
            );
            return Err(e.to_string());
        }

        if let Err(e) = port.flush() {
            error!(
                event = "serial.flush_failed",
                frame_len = bytes.len(),
                "serial flush failed: {}",
                e
            );
            return Err(e.to_string());
        }

        debug!(
            event = "serial.frame_sent",
            command = ?frame.command,
            payload_len = bytes.len(),
            sequence_id = frame.sequence_id,
            "serial frame sent"
        );
        Ok(())
    }

    fn read_response_locked(
        port: &mut dyn SerialPort,
        sequence_id: u32,
        timeout: Duration,
    ) -> Result<SerialResponse, String> {
        port.set_timeout(timeout).map_err(|e| e.to_string())?;

        let mut len_buf = [0u8; 2];
        port.read_exact(&mut len_buf).map_err(|e| {
            warn!(
                event = "serial.read_response_length_failed",
                sequence_id = sequence_id,
                "serial response length read failed: {}",
                e
            );
            e.to_string()
        })?;

        let mut resp_len = u16::from_le_bytes(len_buf) as usize;
        while !(RESPONSE_MIN_LENGTH..=RESPONSE_MAX_LENGTH).contains(&resp_len) {
            len_buf[0] = len_buf[1];
            let mut next = [0u8; 1];
            port.read_exact(&mut next).map_err(|e| {
                warn!(
                    event = "serial.read_response_length_failed",
                    sequence_id = sequence_id,
                    "serial response length resync failed: {}",
                    e
                );
                e.to_string()
            })?;
            len_buf[1] = next[0];
            resp_len = u16::from_le_bytes(len_buf) as usize;
        }

        if resp_len == 0 {
            warn!(
                event = "serial.invalid_response_length",
                sequence_id = sequence_id,
                response_len = resp_len,
                "invalid response length"
            );
            return Err("invalid response length".into());
        }

        let mut resp_buf = vec![0u8; resp_len];
        port.read_exact(&mut resp_buf).map_err(|e| {
            warn!(
                event = "serial.read_response_body_failed",
                sequence_id = sequence_id,
                response_len = resp_len,
                "serial response body read failed: {}",
                e
            );
            e.to_string()
        })?;

        debug!(
            event = "serial.response_received",
            sequence_id = sequence_id,
            response_len = resp_len,
            "serial response received"
        );

        match from_bytes::<SerialResponse>(&resp_buf) {
            Ok(resp) => {
                if !resp.success {
                    warn!(
                        event = "serial.device_error_response",
                        error_code = resp.error_code,
                        sequence_id = resp.sequence_id,
                        "serial error response"
                    );
                }
                Ok(resp)
            }
            Err(e) => {
                error!(
                    event = "serial.decode_failed",
                    sequence_id = sequence_id,
                    "serial response decode failed: {}",
                    e
                );
                Err(e.to_string())
            }
        }
    }

    fn is_final_sign_response(response: &SerialResponse) -> bool {
        let payload = response.payload_bytes();
        if payload.is_empty() {
            return false;
        }

        matches!(
            from_bytes::<SecurePacket>(payload),
            Ok(packet)
                if matches!(
                    packet.payload_type,
                    PacketType::SignResponse | PacketType::ErrorMessage
                )
        )
    }
}
