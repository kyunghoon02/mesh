## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Sepolia: Mesh Passkey Stack 배포

기존에 배포된 P-256 verifier(예: Daimo 배포본)를 재사용할 때:

```shell
$ forge script script/DeployPasskeyStack.s.sol:DeployPasskeyStack \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```

필수 env:

```shell
OWNER=0x...
PASSKEY_PUBKEY=0x...
P256_VERIFIER=0x...    # 기존 배포 verifier 주소
SALT=0x...             # 선택
FACTORY=0x...          # 선택(기존 factory 재사용 시)
```

`DeployPasskeyStack` 실행 후 `Vault linked in script: false`가 나오면(배포 계정 != OWNER):

```shell
$ forge script script/SetPasskeyVerifier.s.sol:SetPasskeyVerifier \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $OWNER_PRIVATE_KEY \
  --broadcast
```

필수 env:

```shell
VAULT=0x...
PASSKEY_VERIFIER=0x...
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
