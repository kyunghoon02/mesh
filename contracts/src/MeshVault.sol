// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPasskeyVerifier} from "./interfaces/IPasskeyVerifier.sol";

/// @title MeshVault - Hardware-rooted SCA
/// @notice Supports owner signatures, optional passkey signatures, and ERC-1271 checks.
contract MeshVault {
    // ERC-1271 return value for valid signatures
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // Prefix used only for passkey signature payload
    bytes1 internal constant PASSKEY_SIG_PREFIX = 0x50;

    address public owner; // Current owner
    bytes public passkeyPubkey; // Stored passkey public key (raw uncompressed x||y)
    address public passkeyVerifier; // Address of passkey verifier contract
    uint256 public recoveryNonce; // nonce for recovery operations

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

    /// @notice Change owner
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "owner=0");
        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
    }

    /// @notice Register or replace passkey pubkey
    function setPasskey(bytes calldata newPubkey) external onlyOwner {
        passkeyPubkey = newPubkey;
        emit PasskeyUpdated(newPubkey);
    }

    /// @notice Register or replace passkey verifier address
    function setPasskeyVerifier(address verifier) external onlyOwner {
        passkeyVerifier = verifier;
        emit PasskeyVerifierUpdated(verifier);
    }

    /// @notice Recover owner via passkey signature
    /// @dev challenge = keccak256("MESH_RECOVER", this, chainid, newOwner, recoveryNonce)
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

    /// @notice ERC-1271 signature verification (owner EOA + optional passkey payload)
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (_isOwnerSignature(hash, signature)) {
            return MAGICVALUE;
        }

        if (_isPasskeySignature(hash, signature)) {
            return MAGICVALUE;
        }

        return 0xffffffff;
    }

    /// @notice Execute one call, owner only
    function execute(address to, uint256 value, bytes calldata data) external onlyOwner returns (bytes memory) {
        require(to != address(0), "to=0");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @notice Execute multiple calls, owner only
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

    /// @dev Owner signature check (ecrecover path)
    function _isOwnerSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        address signer = _recover(hash, signature);
        return signer == owner;
    }

    /// @dev Passkey signature check.
    /// Format:
    /// - [0]: 0x50 prefix
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

        try this._decodePasskeyPayload(payload) returns (bytes memory a, bytes memory c, bytes memory pSig, bytes memory pPub) {
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

        try IPasskeyVerifier(passkeyVerifier).verify(
            authenticatorData,
            clientDataJSON,
            passkeySig,
            passkeyPubkey,
            hash
        ) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev Decode helper for passkey payload
    function _decodePasskeyPayload(bytes memory payload) external pure returns (
        bytes memory authenticatorData,
        bytes memory clientDataJSON,
        bytes memory signature,
        bytes memory pubkey
    ) {
        (authenticatorData, clientDataJSON, signature, pubkey) = abi.decode(
            payload,
            (bytes, bytes, bytes, bytes)
        );
    }

    /// @dev ecrecover helper
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