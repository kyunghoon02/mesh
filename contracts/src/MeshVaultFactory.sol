// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MeshVault} from "./MeshVault.sol";

/// @title MeshVaultFactory - CREATE2 기반 SCA 배포기
/// @notice 유저 EOA가 직접 가스 부담하여 배포하는 모델
contract MeshVaultFactory {
    event AccountCreated(address indexed owner, address indexed account, bytes32 indexed salt);

    /// @notice MeshVault를 CREATE2로 배포
    function createAccount(address owner, bytes calldata passkeyPubkey, bytes32 salt) external returns (address) {
        address account = getAddress(owner, passkeyPubkey, salt);
        if (account.code.length > 0) {
            return account;
        }
        MeshVault vault = new MeshVault{salt: salt}(owner, passkeyPubkey);
        emit AccountCreated(owner, address(vault), salt);
        return address(vault);
    }

    /// @notice 배포될 MeshVault 주소 계산
    function getAddress(address owner, bytes calldata passkeyPubkey, bytes32 salt) public view returns (address) {
        bytes memory initCode = abi.encodePacked(type(MeshVault).creationCode, abi.encode(owner, passkeyPubkey));
        bytes32 hash = keccak256(initCode);
        return _computeCreate2Address(hash, salt);
    }

    function _computeCreate2Address(bytes32 initCodeHash, bytes32 salt) internal view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))));
    }
}
