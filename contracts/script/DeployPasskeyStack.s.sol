// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {MeshVault} from "../src/MeshVault.sol";
import {MeshVaultFactory} from "../src/MeshVaultFactory.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {PasskeyVerifier} from "../src/PasskeyVerifier.sol";

/// @title DeployPasskeyStack
/// @notice Sepolia 기준 Passkey 복구 스택을 한 번에 배포/연결하는 스크립트
/// @dev env:
/// - OWNER (address)                 : MeshVault 소유자(초기 EOA)
/// - PASSKEY_PUBKEY (bytes)          : WebAuthn 공개키(raw x||y 또는 앱에서 정의한 포맷)
/// - SALT (bytes32, optional)        : CREATE2 salt (default: 0x0)
/// - FACTORY (address, optional)     : 기존 MeshVaultFactory 주소
/// - P256_VERIFIER (address, optional): 기존 배포된 P-256 verifier 주소(Daimo 등)
/// - DEPLOY_P256_WRAPPER (bool, optional): true면 P256Verifier(wrapper) 새로 배포
/// - P256_PRECOMPILE (address, optional)  : wrapper가 호출할 precompile 주소(default: 0x100)
/// - SKIP_SET_PASSKEY_VERIFIER (bool, optional): true면 Vault 연결(setPasskeyVerifier) 생략
contract DeployPasskeyStack is Script {
    function run() external {
        address owner = vm.envAddress("OWNER");
        bytes memory passkeyPubkey = vm.envBytes("PASSKEY_PUBKEY");
        bytes32 salt = vm.envOr("SALT", bytes32(0));
        address factoryAddr = vm.envOr("FACTORY", address(0));

        address p256VerifierAddr = vm.envOr("P256_VERIFIER", address(0));
        bool deployP256Wrapper = vm.envOr("DEPLOY_P256_WRAPPER", false);
        address p256Precompile = vm.envOr("P256_PRECOMPILE", address(0x100));
        bool skipSetPasskeyVerifier = vm.envOr("SKIP_SET_PASSKEY_VERIFIER", false);

        require(owner != address(0), "OWNER is required");
        require(passkeyPubkey.length > 0, "PASSKEY_PUBKEY is required");

        vm.startBroadcast();

        // 기존 verifier를 쓰거나, 필요하면 wrapper를 배포한다.
        if (deployP256Wrapper || p256VerifierAddr == address(0)) {
            P256Verifier wrapper = new P256Verifier(p256Precompile);
            p256VerifierAddr = address(wrapper);
        }

        PasskeyVerifier passkeyVerifier = new PasskeyVerifier(p256VerifierAddr);

        MeshVaultFactory factory;
        if (factoryAddr == address(0)) {
            factory = new MeshVaultFactory();
        } else {
            factory = MeshVaultFactory(factoryAddr);
        }

        address predicted = factory.getAddress(owner, passkeyPubkey, salt);
        address deployed = factory.createAccount(owner, passkeyPubkey, salt);

        // 배포 계정이 owner가 아닐 수 있으므로 실패 시 전체 배포를 깨지 않게 처리한다.
        bool linked = false;
        if (!skipSetPasskeyVerifier) {
            try MeshVault(payable(deployed)).setPasskeyVerifier(address(passkeyVerifier)) {
                linked = true;
            } catch {
                linked = false;
            }
        }

        vm.stopBroadcast();

        console2.log("MeshVaultFactory:", address(factory));
        console2.log("Predicted Vault:", predicted);
        console2.log("Deployed Vault:", deployed);
        console2.log("P256 Verifier:", p256VerifierAddr);
        console2.log("Passkey Verifier:", address(passkeyVerifier));
        console2.log("Vault linked in script:", linked);
    }
}
