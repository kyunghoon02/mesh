// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {MeshVault} from "../src/MeshVault.sol";

/// @title SetPasskeyVerifier
/// @notice 이미 배포된 MeshVault에 PasskeyVerifier 주소를 연결하는 스크립트
/// @dev 이 트랜잭션의 서명자는 반드시 MeshVault.owner 이어야 한다.
/// env:
/// - VAULT (address)            : 대상 MeshVault 주소
/// - PASSKEY_VERIFIER (address) : 연결할 PasskeyVerifier 주소
contract SetPasskeyVerifier is Script {
    function run() external {
        address vault = vm.envAddress("VAULT");
        address passkeyVerifier = vm.envAddress("PASSKEY_VERIFIER");

        require(vault != address(0), "VAULT is required");
        require(passkeyVerifier != address(0), "PASSKEY_VERIFIER is required");

        vm.startBroadcast();
        MeshVault(payable(vault)).setPasskeyVerifier(passkeyVerifier);
        vm.stopBroadcast();

        console2.log("Vault:", vault);
        console2.log("PasskeyVerifier set:", passkeyVerifier);
    }
}
