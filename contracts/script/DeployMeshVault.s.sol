// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {MeshVaultFactory} from "../src/MeshVaultFactory.sol";

/// @notice MeshVaultFactory + MeshVault 배포 스크립트
/// @dev env:
/// - OWNER (address)            : SCA 소유자 EOA
/// - PASSKEY_PUBKEY (bytes)     : WebAuthn 공개키(raw)
/// - SALT (bytes32, optional)   : CREATE2 salt (default: 0)
/// - FACTORY (address, optional): 이미 배포된 Factory 주소
contract DeployMeshVault is Script {
    function run() external {
        address owner = vm.envAddress("OWNER");
        bytes memory passkey = vm.envBytes("PASSKEY_PUBKEY");
        bytes32 salt = vm.envOr("SALT", bytes32(0));
        address factoryAddr = vm.envOr("FACTORY", address(0));

        vm.startBroadcast();

        MeshVaultFactory factory;
        if (factoryAddr == address(0)) {
            factory = new MeshVaultFactory();
        } else {
            factory = MeshVaultFactory(factoryAddr);
        }

        address predicted = factory.getAddress(owner, passkey, salt);
        address deployed = factory.createAccount(owner, passkey, salt);

        vm.stopBroadcast();

        console2.log("Factory:", address(factory));
        console2.log("Predicted:", predicted);
        console2.log("Deployed:", deployed);
    }
}
