# Mesh: Universal Hardware 2FA Infrastructure

"No Mnemonics. No Compromise. Pure Hardware Security."

Mesh는 기존 소프트웨어 지갑의 편의성을 유지하면서, 인터넷과 격리된 하드웨어 버튼 승인 없이는 자산 이동이 불가능하도록 설계된 고유 보안 아키텍처입니다. RPC 레벨에서 작동하는 보안 레이어를 통해 특정 dApp 종속 없이 범용적으로 적용되는 것을 목표로 합니다.

---

## Key Features

- **Mnemonic-less UX**: 12단어 니모닉을 적거나 보관할 필요가 없습니다. 하드웨어 내부에서 생성된 격리된 키를 사용합니다.
- **Passkey Recovery**: 기기를 분실하더라도 스마트폰의 FaceID나 지문(WebAuthn)을 통해 온체인에서 안전하게 권한을 복구합니다.
- **Air-Gapped Signer**: 서명 전용 노드(Node A)는 인터넷 스택이 제거된 상태로 무전(ESP-NOW) 통신만을 사용하여 원격 해킹을 원천 차단합니다.
- **Universal RPC Proxy**: 메타마스크의 RPC 설정만으로 모든 dApp에 즉시 하드웨어 2FA를 적용할 수 있습니다.
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
