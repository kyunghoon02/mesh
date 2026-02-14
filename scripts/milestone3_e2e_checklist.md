# Milestone 3 E2E 데모 체크리스트 (포트폴리오용)

이 문서는 Node B 경유 서명 승인 흐름 점검 순서를 정리한 것입니다.

## 0) 실행 전 점검
- relayer `.env` 필수값
  - `UPSTREAM_RPC` : 테스트넷/메인넷 RPC URL
  - `EOA_ADDRESS` : 운영자 EOA 주소
  - `DATABASE_URL` : PostgreSQL 연결 문자열
  - `SERIAL_PORT` : 미연결이면 비워둠(이때는 Node B 상태 체크가 실패로 표시될 수 있음)
- relayer 실행: `cargo run` (relayer 폴더)

## 1) Node B 미연결 모드 스모크 체크

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e_nodeb_relayer_check.ps1 `
  -RpcUrl "http://localhost:8080" `
  -StatusRepeat 3 -StatusIntervalMs 500 `
  -SkipNodeB
```

### 기대 결과
- `mesh_getStatus`: `SERIAL_PORT not configured` 또는 장치 미연결 에러가 경고 처리
- `eth_chainId` / `mesh_getChainConfig`: 환경에 따라 OK 또는 경고
- `eth_call`/`eth_sendTransaction`: 업스트림 또는 하드웨어 경로 상태가 명확히 반환

## 2) Node B 연결 모드 점검

1. Node B USB 포트 확인 후 `SERIAL_PORT` 설정
   - 예: `SERIAL_PORT=COM4` (Windows) 또는 `/dev/ttyUSB0` (Linux)
2. relayer 재실행

```bash
SERIAL_PORT=/dev/ttyUSB0 \
SERIAL_BAUD=115200 \
UPSTREAM_RPC=<YOUR_RPC_URL> \
EOA_ADDRESS=<EOA> \
cargo run
```

3. 강제 점검

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e_nodeb_relayer_check.ps1 `
  -RpcUrl "http://localhost:8080" `
  -StatusRepeat 8 -StatusIntervalMs 300
```

### 기대 결과
- `mesh_getStatus`가 정상 응답
- Node B 로그에 GET_STATUS / SignRequest 포워딩 확인

## 3) Core UX 데모 시퀀스
1. dApp 또는 `eth_call`/`eth_sendTransaction` dry-run으로 트랜잭션 요청
2. Node B 로그: SignRequest 수신 + ESP-NOW 전송
3. Node A LCD: 승인/거절 화면(요약 문자열 + 버튼) 표시
4. 승인 버튼 탭 시: 서명 응답 반환
5. Node B 로그: ESP-NOW 응답 수신 및 serial 응답 반환
6. relayer: tx 서명 결과 반환

## 4) 디버깅 우선순위
1. Node B 연결 실패: `serial open failed`, 포트 권한/드라이버 확인
2. Node A 페어링 실패: `GetPeerInfo / ConfirmPairing` 처리 점검
3. 서명 실패: `ciphertext_len`, `auth_tag`, 카운터/nonce 연동 점검
4. relayer는 하드웨어 연결이 없으면 `SERIAL_PORT not configured`를 명시적으로 반환
