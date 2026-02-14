# Milestone 3 E2E 데모 체크리스트 (포트폴리오용)

이 문서는 **Node B 경유 서명 승인 흐름**을 포트폴리오 데모로 재현하기 위한 실행 순서를 정리합니다.

## 0) 실행 전 점검
- relayer `.env` 최소값
  - `UPSTREAM_RPC` : 테스트넷/메인넷 RPC
  - `EOA_ADDRESS` : 본인 EOA
  - `DATABASE_URL` : PostgreSQL 연결
  - `APPROVAL_MODE=pass` (하드웨어 미연결 테스트)
  - `SERIAL_PORT` 없음 (Node B 미연결 환경)
- relayer 실행: `cargo run` (relayer 폴더)

## 1) Node B 미연결 모드 스모크 체크 (현재 하드웨어 준비 전)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e_nodeb_relayer_check.ps1 \
  -RpcUrl "http://localhost:8080" \
  -StatusRepeat 3 -StatusIntervalMs 500 \
  -SkipNodeB
```

### 기대 결과
- `mesh_getStatus`는 `SERIAL_PORT not configured` 에러를 경고로만 남김
- `eth_chainId` / `mesh_getChainConfig`는 환경에 따라 OK or 경고
- `eth_call`/`eth_sendTransaction`은 relayer가 통과 또는 명확한 거절 사유를 반환

## 2) Node B 연결 모드(실제 연동) 점검

1. Node B USB 직렬 포트를 확인하고 relayer에 연결
   - 예: `SERIAL_PORT=COM4` (Windows) 또는 `/dev/ttyUSB0` (Linux)
2. relayer 재실행

```bash
APPROVAL_MODE=pass \
SERIAL_PORT=/dev/ttyUSB0 \
SERIAL_BAUD=115200 \
UPSTREAM_RPC=<YOUR_RPC_URL> \
EOA_ADDRESS=<EOA> \
cargo run
```

3. 강제 점검:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e_nodeb_relayer_check.ps1 \
  -RpcUrl "http://localhost:8080" \
  -StatusRepeat 8 -StatusIntervalMs 300
```

### 기대 결과
- `mesh_getStatus`가 정상 응답
- Node B 로그에 GET_STATUS / SignRequest 핸드셰이크가 보여야 함

## 3) 실제 Core UX 데모(권장 시퀀스)
1. dApp(또는 `eth_call`/`eth_sendTransaction` dry-run)로 트랜잭션 요청
2. Node B 로그: SignRequest 수신 + ESP-NOW 전송
3. Node A LCD: 승인 화면(요약 문자열 + 진행 버튼) 표시
4. 버튼 1회 탭: 승인 후 서명
5. Node B 로그: ESP-NOW 응답 수신 및 serial 응답 반환
6. relayer: tx 서명 결과 반환

## 4) 포트폴리오 캡처 항목(권장)
- Node B 시리얼 로그 (GET_STATUS, SignRequest, 포워딩/응답)
- Node A 화면(승인/거부 UI)
- 브라우저에서 relayer 응답 로그
- e2e 스크립트 결과(`요약: OK/ WARN/ FAIL`)

## 5) 실패 포인트를 줄이는 디버깅 우선순위
1) Node B 연결 실패: relayer `Serial open failed`, 포트/권한 확인
2) Node A 페어링 실패: Node B에서 `GetPeerInfo/ConfirmPairing` 재시도
3) 서명 실패: Node A의 `ciphertext_len`, `auth_tag`, 재시도 카운터 확인
4) relayer `APPROVAL_MODE`: HARDWARE_REQUIRED(=block)면 하드웨어 미연결 시 즉시 거부
