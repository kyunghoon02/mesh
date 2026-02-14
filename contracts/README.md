# Mesh Contracts

## 환경 구성

필요한 라이브러리는 소스 트리에 커밋하지 않고, 실행 시 설치합니다.

```bash
cd contracts
forge install
```

`forge-std`가 아직 설치되어 있지 않다면 아래 명령어로 수동 설치 가능합니다.

```bash
cd contracts
forge install foundry-rs/forge-std
```

`foundry.toml`에는 다음 설정이 유지되어 있어야 합니다.

- `libs = ["lib"]`

## 기본 사용법

- 빌드

```bash
cd contracts
forge build
```

- 테스트

```bash
cd contracts
forge test
```

- 포맷

```bash
cd contracts
forge fmt
```

- 배포 예시 (Sepolia)

```bash
cd contracts
forge script script/DeployPasskeyStack.s.sol:DeployPasskeyStack \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```

- 패스키 검증기 연결 예시

```bash
cd contracts
forge script script/SetPasskeyVerifier.s.sol:SetPasskeyVerifier \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $OWNER_PRIVATE_KEY \
  --broadcast
```

## 주의

- 이 저장소는 `contracts/lib` 폴더를 `.gitignore`로 제외하므로 라이브러리 코드는 커밋되지 않습니다.
- 처음 클론한 뒤 실행 전에 반드시 `forge install` 또는 `forge install foundry-rs/forge-std`를 먼저 수행하세요.
