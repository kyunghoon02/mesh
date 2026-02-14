# Mesh Firmware (Node A / Node B)

이 디렉토리는 `ESP32-S3(Node A)`와 `ESP32-C3(Node B)` 펌웨어를 포함합니다.

## 지금은 테스트 미실행(하드웨어 미연결) 기준으로 할 일

- 런타임 테스트(`flash`, 시리얼 송수신, GPIO 입력)는 하드웨어를 붙인 뒤에 진행합니다.
- 지금은 코드 정합성 정리와 빌드 전제 조건 점검만 수행합니다.

## 빌드 전제 조건 (필수)

Node A / Node B는 타겟별 `no_std` 크로스 컴파일이 필요합니다.

- `esp` 전용 Rust 타겟이 준비되어 있어야 합니다.
- 릴리스 환경에서는 `cargo` 타깃 기반 명령이 실패하지 않아야 합니다.
- 아래 명령은 하드웨어가 있을 때 실제로 수행해야 하는 예시입니다.

```bash
# 예시 (환경에 맞춰 실제 명령은 다를 수 있음)
cd /mnt/c/Github/mesh
cargo install --git https://github.com/esp-rs/espup cargo-espflash
rustup toolchain install nightly
espup install
```

## 현재 상태에서 바로 할 수 있는 점검

- ESP 타겟이 없더라도 `common` / `relayer` 쪽 정적 컴파일은 수행 가능합니다.
- `node-a-signer`, `node-b-gateway`는 하드웨어 타겟이 준비된 뒤 확인해야 합니다.

## 실행 플로우(하드웨어 준비 후)

1. Node B 펌웨어 플래시
2. Node A 펌웨어 플래시
3. Relayer 실행
4. Node B/Node A 동작 유무를 확인한 뒤 E2E 스크립트를 차례대로 실행

> 하드웨어가 없을 때는 테스트 스크립트에서 Node B/USB 시리얼 의존 단계가 실패할 수 있습니다.
