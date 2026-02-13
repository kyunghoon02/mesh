// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPasskeyVerifier} from "./interfaces/IPasskeyVerifier.sol";

/// @title MeshVault - 최소 구현 SCA
/// @notice EOA(하드웨어) 소유자 + Passkey(P-256) 공개키 보관 + ERC-1271 검증
contract MeshVault {
    // ERC-1271 magic value
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    address public owner;               // 현재 하드웨어 서명자
    bytes public passkeyPubkey;         // WebAuthn P-256 공개키
    address public passkeyVerifier;     // P-256/WebAuthn 검증 컨트랙트
    uint256 public recoveryNonce;       // 복구 리플레이 방지

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event PasskeyUpdated(bytes newPubkey);
    event PasskeyVerifierUpdated(address verifier);
    event Recovery(address indexed newOwner, uint256 indexed nonce);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address owner_, bytes memory passkeyPubkey_) {
        require(owner_ != address(0), "owner=0");
        owner = owner_;
        passkeyPubkey = passkeyPubkey_;
    }

    /// @notice 소유자(하드웨어 키) 변경
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "owner=0");
        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
    }

    /// @notice Passkey 공개키 갱신 (EOA 소유자만)
    function setPasskey(bytes calldata newPubkey) external onlyOwner {
        passkeyPubkey = newPubkey;
        emit PasskeyUpdated(newPubkey);
    }

    /// @notice Passkey 검증 컨트랙트 주소 설정
    function setPasskeyVerifier(address verifier) external onlyOwner {
        passkeyVerifier = verifier;
        emit PasskeyVerifierUpdated(verifier);
    }

    /// @notice Passkey로 소유자 복구
    /// @dev challenge = keccak256("MESH_RECOVER", this, chainid, newOwner, nonce)
    function recoverOwner(
        address newOwner,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes calldata signature
    ) external {
        require(passkeyVerifier != address(0), "verifier not set");
        require(newOwner != address(0), "owner=0");

        bytes32 challenge = keccak256(
            abi.encodePacked("MESH_RECOVER", address(this), block.chainid, newOwner, recoveryNonce)
        );

        bool ok = IPasskeyVerifier(passkeyVerifier).verify(
            authenticatorData,
            clientDataJSON,
            signature,
            passkeyPubkey,
            challenge
        );
        require(ok, "invalid passkey");

        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
        emit Recovery(newOwner, recoveryNonce);
        recoveryNonce++;
    }

    /// @notice ERC-1271 메시지 서명 검증 (EOA 서명 기반)
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        address signer = _recover(hash, signature);
        if (signer == owner) {
            return MAGICVALUE;
        }
        return 0xffffffff;
    }

    /// @notice 단일 트랜잭션 실행 (EOA 소유자만)
    function execute(address to, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        require(to != address(0), "to=0");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @notice 배치 실행
    function executeBatch(
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data
    ) external onlyOwner returns (bytes[] memory results) {
        require(to.length == value.length && to.length == data.length, "len mismatch");
        results = new bytes[](to.length);
        for (uint256 i = 0; i < to.length; i++) {
            require(to[i] != address(0), "to=0");
            (bool ok, bytes memory ret) = to[i].call{value: value[i]}(data[i]);
            require(ok, "call failed");
            results[i] = ret;
        }
    }

    receive() external payable {}

    function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}