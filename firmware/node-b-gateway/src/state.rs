/// Node B 상태 머신
/// 보안 정책: 부팅 후 5분 이내에만 페어링 허용
/// 또는 버튼 조합 입력 시 허용 (추후 구현 예정)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// 아직 peer 설정 없음
    Unpaired,
    /// 현재 페어링 모드, Node A 확인 대기중
    Pairing,
    /// 페어링 성공, 서명 요청 준비 완료
    Ready,
}

pub struct StateManager {
    state: PairingState,
    peer_mac: Option<[u8; 6]>,
    boot_time_ms: u64,
    pairing_window_ms: u64, // 기본값 5분 (300_000 ms)
}

impl StateManager {
    pub fn new(boot_time_ms: u64) -> Self {
        Self {
            state: PairingState::Unpaired,
            peer_mac: None,
            boot_time_ms,
            pairing_window_ms: 300_000, // 5분
        }
    }

    pub fn state(&self) -> PairingState {
        self.state
    }

    pub fn peer_mac(&self) -> Option<[u8; 6]> {
        self.peer_mac
    }

    /// 시간 윈도우 기반으로 페어링 가능 여부 확인
    pub fn can_enter_pairing(&self, current_time_ms: u64) -> bool {
        match self.state {
            PairingState::Unpaired => {
                // 부팅 후 페어링 윈도우 내에만 허용
                (current_time_ms - self.boot_time_ms) < self.pairing_window_ms
            }
            PairingState::Pairing => true, // 이미 페어링 모드
            PairingState::Ready => false,  // 이미 페어링 완료
        }
    }

    /// 페어링 모드 진입 (보안 게이트: 시간 윈도우 확인)
    pub fn enter_pairing(&mut self, current_time_ms: u64) -> Result<(), PairingError> {
        if !self.can_enter_pairing(current_time_ms) {
            return Err(PairingError::WindowExpired);
        }

        self.state = PairingState::Pairing;
        Ok(())
    }

    /// Node A MAC 주소로 페어링 확정
    pub fn confirm_pairing(&mut self, mac: [u8; 6]) -> Result<(), PairingError> {
        if self.state != PairingState::Pairing {
            return Err(PairingError::InvalidState);
        }

        self.peer_mac = Some(mac);
        self.state = PairingState::Ready;
        Ok(())
    }

    /// 서명 요청 가능 여부 확인
    pub fn can_sign(&self) -> bool {
        self.state == PairingState::Ready
    }

    /// 페어링 리셋 (테스트 또는 공장 초기화용)
    pub fn reset(&mut self) {
        self.state = PairingState::Unpaired;
        self.peer_mac = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// 페어링 윈도우 만료
    WindowExpired,
    /// 잘못된 상태에서 호출
    InvalidState,
}
