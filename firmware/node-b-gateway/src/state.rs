#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// 아직 페어링되지 않은 상태
    Unpaired,
    /// 페어링 시도 중 상태. Node A에 페어링 정보 승인이 필요
    Pairing,
    /// 페어링 완료 상태. 하드웨어 승인 완료 후 자동으로 작동
    Ready,
}

pub struct StateManager {
    state: PairingState,
    peer_mac: Option<[u8; 6]>,
    boot_time_ms: u64,
    pairing_window_ms: u64, // 부팅 후 5분(300_000ms) 안에만 허용
}

impl StateManager {
    pub fn new(boot_time_ms: u64) -> Self {
        Self {
            state: PairingState::Unpaired,
            peer_mac: None,
            boot_time_ms,
            pairing_window_ms: 300_000,
        }
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn peer_mac(&self) -> Option<[u8; 6]> {
        self.peer_mac
    }

    /// 부팅 5분 이내에만 페어링 진입을 허용한다.
    pub fn can_enter_pairing(&self, current_time_ms: u64) -> bool {
        match self.state {
            PairingState::Unpaired => {
                (current_time_ms - self.boot_time_ms) < self.pairing_window_ms
            }
            PairingState::Pairing => true,
            PairingState::Ready => false,
        }
    }

    /// 페어링 진입 시도
    pub fn enter_pairing(&mut self, current_time_ms: u64) -> Result<(), PairingError> {
        if !self.can_enter_pairing(current_time_ms) {
            return Err(PairingError::WindowExpired);
        }

        self.state = PairingState::Pairing;
        Ok(())
    }

    /// 페어링 완료 후 Peer MAC 확인해 READY 상태로 전환
    pub fn confirm_pairing(&mut self, mac: [u8; 6]) -> Result<(), PairingError> {
        if self.state != PairingState::Pairing {
            return Err(PairingError::InvalidState);
        }

        self.peer_mac = Some(mac);
        self.state = PairingState::Ready;
        Ok(())
    }

    /// 부팅 시 저장된 Peer MAC이 있으면 READY 상태로 복귀
    pub fn restore_paired(&mut self, mac: [u8; 6]) {
        self.peer_mac = Some(mac);
        self.state = PairingState::Ready;
    }

    /// 하드웨어 서명 허용 여부
    pub fn can_sign(&self) -> bool {
        self.state == PairingState::Ready
    }

    /// 페어링 상태 초기화
    pub fn reset(&mut self) {
        self.state = PairingState::Unpaired;
        self.peer_mac = None;
    }

    /// 페어링 진행 시간이 만료되면 상태를 Unpaired로 되돌린다.
    /// 만료되었을 때 true, 아니면 false를 반환한다.
    pub fn expire_pairing_if_needed(&mut self, current_time_ms: u64) -> bool {
        let should_expire = match self.state {
            PairingState::Pairing => !self.can_enter_pairing(current_time_ms),
            _ => false,
        };

        if should_expire {
            self.reset();
            return true;
        }

        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// 페어링 시간이 만료됨
    WindowExpired,
    /// 페어링 상태가 유효하지 않음
    InvalidState,
}
