# Mesh: Universal Hardware 2FA Infrastructure

"No Mnemonics. No Compromise. Pure Hardware Security."

Mesh는 기존 소프트웨어 지갑의 편의성을 유지하면서, 인터넷과 격리된 하드웨어 버튼 승인 없이는 자산 이동이 불가능하도록 설계된 고유 보안 아키텍처입니다. 로컬 relayer와 하드웨어 signer를 통해 실제 EVM 서명 요청을 처리할 수 있으며, 범용 dApp 호환을 목표로 확장되고 있습니다.

---

## Key Features

- **Mnemonic-less UX**: 12단어 니모닉을 적거나 보관할 필요가 없습니다. 하드웨어 내부에서 생성된 격리된 키를 사용합니다.
- **Passkey Recovery**: 기기를 분실하더라도 스마트폰의 FaceID나 지문(WebAuthn)을 통해 온체인에서 안전하게 권한을 복구합니다.
- **Air-Gapped Signer**: 서명 전용 노드(Node A)는 인터넷 스택이 제거된 상태로 무전(ESP-NOW) 통신만을 사용하여 원격 해킹을 원천 차단합니다.
- **Hardware Approval Relayer**: 로컬 relayer를 통해 EVM 서명 요청을 하드웨어 승인 플로우로 연결합니다.
- **ERC-4337 Foundation**: 계정 추상화를 통해 유연한 복구 로직과 강력한 보안 정책을 온체인에서 강제합니다.
- **Hybrid Account Mode**: 체인별로 EOA 기본 + SCA 온디맨드 배포를 지원합니다. (유저 가스 부담)

---

## Architecture Layers

| Layer    | Component    | Hardware  | Role                                                       |
| -------- | ------------ | --------- | ---------------------------------------------------------- |
| L1       | Mesh Relayer | Server    | Smart Firewall. RPC 프록시 및 패스키 복구 인터페이스 제공. |
| L2       | Mesh Link    | ESP32-C3  | Secure Bridge. 인터넷과 에어갭 장치를 잇는 암호화 중계기.  |
| L3       | Mesh Vault   | LilyGO S3 | Root of Trust. 하드웨어 키 생성 및 물리적 버튼 승인.       |
| On-chain | Smart Wallet | EVM Chain | Final Judge. 하드웨어 서명 및 패스키 복구 로직 실행.       |

---

## Current Working Scope

- **Live Signing Flow**: Node A (LilyGO S3) + Node B (ESP32-C3) + Relayer 구성이 실제 하드웨어에서 빌드/플래시되어 동작합니다.
- **Human Approval Loop**: 페어링 요청, 서명 요청, 물리 버튼 승인/거절, 최종 서명 반환까지 end-to-end로 검증되었습니다.
- **Local Self-Hosted Stack**: 로컬 환경에서 relayer RPC를 통해 `eth_sign` 플로우를 실제로 수행할 수 있습니다.
- **Forward Compatibility**: 현재는 로컬 relayer 중심으로 안정화되어 있으며, 범용 dApp/provider 호환성은 다음 단계로 확장 중입니다.

---

## Project Structure

```
mesh/
├── common/             # Zero-alloc shared protocol definitions
├── contracts/          # Solidity SCA/Factory (Foundry)
├── firmware/           # MCU-specific implementations
│   ├── node-a-signer/  # LilyGO S3 (Root of Trust, UI, Key Storage)
│   └── node-b-gateway/ # ESP32-C3 (Hybrid Bridge: Serial/WS to ESP-NOW)
├── relayer/            # Rust-based Intelligent Firewall (Local/Cloud)
└── partitions.csv      # Global hardware memory map
```

---

## Tech Stack

- **Crypto**: secp256k1 (k256), Keccak256 (sha3), ChaCha20-Poly1305
- **Embedded**: esp-hal (bare-metal), esp-storage (flash access)
- **Serialization**: postcard (compact binary format)
- **UI**: embedded-graphics, qrcodegen-no-heap
- **Backend**: Rust (axum, tokio), PostgreSQL
- **Smart Contracts**: Foundry

---

## Recovery Model: The Passkey Bridge

- **등록**: 지갑 생성 시 본인의 스마트폰 생체 인증을 복구 키로 등록.
- **분실**: 하드웨어 분실 시 대시보드 접속.
- **인증**: 스마트폰 지문/FaceID 인증으로 본인 증명.
- **복구**: 온체인 컨트랙트가 새 하드웨어를 즉시 마스터 키로 승인.

---

## Hybrid Account Mode (EOA + SCA)

- **EOA 기본**: SCA가 아직 배포되지 않은 체인은 EOA 주소로 동작합니다.
- **SCA 온디맨드 배포**: 사용자가 체인을 활성화하면 MeshVaultFactory로 SCA를 배포합니다.
- **주소 예측**: CREATE2 기반으로 배포 전에도 SCA 주소를 예측합니다.

---

## Relayer RPC Extensions

- `mesh_prepareDeploy`: SCA 배포 트랜잭션 생성 + 예상 주소 반환
- `mesh_confirmDeploy`: 배포 트랜잭션 상태 확인 및 체인 레지스트리 갱신
- `mesh_getChainConfig`: 체인별 모드/주소 조회
- `mesh_setChainConfig`: 체인별 모드/주소 설정

## E2E 연동 점검

아래 스크립트를 통해 연동 점검을 수행합니다.

`scripts/e2e_nodeb_relayer_check.ps1`
- 기본 실행: `-SkipNodeB` 모드 (Node B 미연결 테스트)
- 하드웨어 연결 후 실제 연동 점검: `-SkipNodeB` 없이 실행
- 상세 체크리스트: `scripts/milestone3_e2e_checklist.md`

- 요청: `mesh_getStatus` (반복)
  - 동작: `SERIAL` 상태 조회 요청을 반복 전송
  - 기대 결과: 상태 값이 연속적으로 응답되고, 요청 ID/시퀀스가 일관되게 증가

- 요청: `eth_chainId`
  - 동작: 현재 연결 체인 ID 조회
  - 기대 결과: 체인 ID(hex string) 반환

- 요청: `mesh_getChainConfig`
  - 동작: 체인별 저장 설정 조회
  - 기대 결과: `chain_id / mode / factory_address / rpc_url / sca_address / status` 반환

- 요청: `eth_sendTransaction` 또는 `eth_call` dry-run
  - 동작: 하드웨어 경유 트랜잭션을 시뮬레이션
  - 기대 결과: 하드웨어 승인 경로(설정) 또는 업스트림 에러 코드가 명확하게 반환

### Node B 미연결 모드 실행 예시

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\e2e_nodeb_relayer_check.ps1 `
  -RpcUrl "http://127.0.0.1:18080" `
  -StatusRepeat 3 `
  -StatusIntervalMs 500 `
  -SkipNodeB
```

실제 하드웨어(Node A, Node B)가 있어야 `mesh_getStatus` 및 하드웨어 경유 트랜잭션 플로우를 완전히 점검할 수 있습니다.

## dApp 로그인 호환성 점검 (Core)

Relayer가 dApp에 노출하는 계정이 SCA로 바뀌는지 확인하는 최소 체크리스트입니다.

- `eth_accounts`를 호출했을 때 결과 배열이 SCA 주소를 반영하는지 확인
- `eth_requestAccounts`에서 같은 주소가 반환되는지 확인
- `mesh_getChainConfig`에서 `mode: SCA`, `status: active`, `sca_address`가 올바른지 확인
- `wallet_reconnect` 또는 dApp 재접속 후에도 계정 값이 유지되는지 확인

예시:

```bash
curl http://127.0.0.1:18080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}'

curl http://127.0.0.1:18080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"eth_requestAccounts","params":[]}'

curl http://127.0.0.1:18080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"mesh_getChainConfig","params":[{"chain_id":"0xaa36a7"}]}'
```

기대 응답:

```json
{"jsonrpc":"2.0","id":1,"result":["0x...sca..."]}
```

실패 시 확인 포인트:

- `result`가 빈 배열이면, `EOA_ADDRESS`, `SCA` 활성화/상태, `chain_id` 조회 과정을 점검
- 값이 비어있는 경우 `resolve_account`가 `[]`를 반환하도록 변경되었기 때문에 빈 배열 자체는 런타임 안전 동작입니다.

## Positioning

- Mesh는 "RPC 엔드포인트만 바꿔 모든 기존 지갑을 완전히 대체하는 범용 지갑"이라기보다, 하드웨어 승인형 서명 시스템을 실제 동작하는 형태로 구현한 self-hosted wallet stack입니다.
- 현재 강점은 **실제 하드웨어 서명 플로우가 작동한다는 점**이며, 이후 단계에서 provider/extension 레이어를 추가해 범용 dApp 호환성을 넓혀갈 수 있습니다.
