// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPasskeyVerifier} from "./interfaces/IPasskeyVerifier.sol";

/// @title MeshVault - 하드웨어 루트 SCA
/// @notice 소유자 서명, 패스키 선택 서명, ERC-1271 검증을 모두 지원한다.
contract MeshVault {
    // ERC-1271에서 유효 서명 판정용 반환값
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // 패스키 서명 페이로드 구분용 접두사
    bytes1 internal constant PASSKEY_SIG_PREFIX = 0x50;

    address public owner; // 현재 소유자 주소
    bytes public passkeyPubkey; // 저장된 패스키 공개키(x||y, 압축 해제 원본)
    address public passkeyVerifier; // 패스키 검증 컨트랙트 주소
    uint256 public recoveryNonce; // 복구 요청 카운터

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

    /// @notice 소유자 변경
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "owner=0");
        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
    }

    /// @notice 패스키 공개키 등록/교체
    function setPasskey(bytes calldata newPubkey) external onlyOwner {
        passkeyPubkey = newPubkey;
        emit PasskeyUpdated(newPubkey);
    }

    /// @notice 패스키 검증 컨트랙트 주소 등록/교체
    function setPasskeyVerifier(address verifier) external onlyOwner {
        passkeyVerifier = verifier;
        emit PasskeyVerifierUpdated(verifier);
    }

    /// @notice 패스키 서명 기반 소유자 복구
    /// @dev challenge = keccak256("MESH_RECOVER", this, chainid, newOwner, recoveryNonce)
    function recoverOwner(
        address newOwner,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes calldata signature
    ) external {
        require(passkeyVerifier != address(0), "verifier not set");
        require(newOwner != address(0), "owner=0");

        bytes32 challenge =
            keccak256(abi.encodePacked("MESH_RECOVER", address(this), block.chainid, newOwner, recoveryNonce));

        bool ok = IPasskeyVerifier(passkeyVerifier)
            .verify(authenticatorData, clientDataJSON, signature, passkeyPubkey, challenge);
        require(ok, "invalid passkey");

        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
        emit Recovery(newOwner, recoveryNonce);
        recoveryNonce++;
    }

    /// @notice ERC-1271 서명 검증(EOA 서명 또는 패스키 페이로드)
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (_isOwnerSignature(hash, signature)) {
            return MAGICVALUE;
        }

        if (_isPasskeySignature(hash, signature)) {
            return MAGICVALUE;
        }

        return 0xffffffff;
    }

    /// @notice 단일 트랜잭션 실행(소유자만 가능)
    function execute(address to, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        require(to != address(0), "to=0");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @notice 다중 트랜잭션 실행(소유자만 가능)
    function executeBatch(address[] calldata to, uint256[] calldata value, bytes[] calldata data)
        external
        onlyOwner
        returns (bytes[] memory results)
    {
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

    /// @dev 소유자 ECDSA 서명 검증 경로
    function _isOwnerSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        address signer = _recover(hash, signature);
        return signer == owner;
    }

    /// @dev 패스키 서명 검증.
    /// 형식:
    /// - [0]: 0x50 접두사
    /// - [1:]: abi.encode(authenticatorData, clientDataJSON, signature, pubkey)
    function _isPasskeySignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signature.length < 1 || signature[0] != PASSKEY_SIG_PREFIX) {
            return false;
        }
        if (passkeyVerifier == address(0) || passkeyPubkey.length == 0) {
            return false;
        }

        bytes memory payload = signature[1:];
        bytes memory authenticatorData;
        bytes memory clientDataJSON;
        bytes memory passkeySig;
        bytes memory passkeyPub;

        try this._decodePasskeyPayload(payload) returns (
            bytes memory a, bytes memory c, bytes memory pSig, bytes memory pPub
        ) {
            authenticatorData = a;
            clientDataJSON = c;
            passkeySig = pSig;
            passkeyPub = pPub;
        } catch {
            return false;
        }

        if (passkeyPub.length != passkeyPubkey.length) {
            return false;
        }
        if (keccak256(passkeyPub) != keccak256(passkeyPubkey)) {
            return false;
        }

        try IPasskeyVerifier(passkeyVerifier)
            .verify(authenticatorData, clientDataJSON, passkeySig, passkeyPubkey, hash) returns (
            bool ok
        ) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev 패스키 페이로드 디코드 헬퍼
    function _decodePasskeyPayload(bytes memory payload)
        external
        pure
        returns (
            bytes memory authenticatorData,
            bytes memory clientDataJSON,
            bytes memory signature,
            bytes memory pubkey
        )
    {
        (authenticatorData, clientDataJSON, signature, pubkey) = abi.decode(payload, (bytes, bytes, bytes, bytes));
    }

    /// @dev ecrecover 헬퍼
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
