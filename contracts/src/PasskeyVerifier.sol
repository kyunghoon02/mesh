// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPasskeyVerifier} from "./interfaces/IPasskeyVerifier.sol";
import {IP256Verifier} from "./interfaces/IP256Verifier.sol";

/// @title PasskeyVerifier
/// @notice WebAuthn 서명 검증을 외부 P-256 Verifier에 위임
/// @dev challenge(JSON 파싱)는 현재 구현하지 않음
contract PasskeyVerifier is IPasskeyVerifier {
    bytes internal constant BASE64URL_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    address public owner;
    address public p256Verifier;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event VerifierUpdated(address verifier);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address verifier) {
        owner = msg.sender;
        p256Verifier = verifier;
        emit OwnershipTransferred(address(0), msg.sender);
        emit VerifierUpdated(verifier);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "owner=0");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice P-256 Verifier 주소 갱신
    function setP256Verifier(address verifier) external onlyOwner {
        p256Verifier = verifier;
        emit VerifierUpdated(verifier);
    }

    function verify(
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes calldata signature,
        bytes calldata pubkey,
        bytes32 expectedChallenge
    ) external view override returns (bool) {
        if (p256Verifier == address(0)) {
            return false;
        }
        if (!_matchesClientData(clientDataJSON, expectedChallenge)) {
            return false;
        }

        // WebAuthn 서명 입력: SHA256(authenticatorData || SHA256(clientDataJSON))
        bytes32 clientHash = sha256(clientDataJSON);
        bytes32 msgHash = sha256(abi.encodePacked(authenticatorData, clientHash));

        return IP256Verifier(p256Verifier).verify(msgHash, signature, pubkey);
    }

    function _matchesClientData(bytes calldata clientDataJSON, bytes32 expectedChallenge) internal pure returns (bool) {
        bytes memory challengeValue = bytes(_base64Url(abi.encodePacked(expectedChallenge)));
        return _matchJsonStringField(clientDataJSON, "type", bytes("webauthn.get"))
            && _matchJsonStringField(clientDataJSON, "challenge", challengeValue);
    }

    function _matchJsonStringField(bytes calldata json, string memory key, bytes memory expectedValue)
        internal
        pure
        returns (bool)
    {
        bytes memory keyBytes = bytes(key);

        for (uint256 i = 0; i < json.length; i++) {
            if (json[i] != 0x22) {
                continue;
            }

            if (!_matchesAt(json, i + 1, keyBytes)) {
                continue;
            }

            uint256 cursor = i + 1 + keyBytes.length;
            if (cursor >= json.length || json[cursor] != 0x22) {
                continue;
            }
            cursor++;
            cursor = _skipSpaces(json, cursor);
            if (cursor >= json.length || json[cursor] != ':') {
                continue;
            }
            cursor++;
            cursor = _skipSpaces(json, cursor);
            if (cursor >= json.length || json[cursor] != 0x22) {
                continue;
            }
            cursor++;

            if (!_matchesAt(json, cursor, expectedValue)) {
                continue;
            }

            cursor += expectedValue.length;
            return cursor < json.length && json[cursor] == 0x22;
        }

        return false;
    }

    function _matchesAt(bytes calldata data, uint256 offset, bytes memory expected) internal pure returns (bool) {
        if (offset + expected.length > data.length) {
            return false;
        }

        for (uint256 i = 0; i < expected.length; i++) {
            if (data[offset + i] != expected[i]) {
                return false;
            }
        }

        return true;
    }

    function _skipSpaces(bytes calldata data, uint256 cursor) internal pure returns (uint256) {
        while (cursor < data.length) {
            bytes1 ch = data[cursor];
            if (ch != 0x20 && ch != 0x09 && ch != 0x0a && ch != 0x0d) {
                break;
            }
            cursor++;
        }
        return cursor;
    }

    function _base64Url(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) {
            return "";
        }

        uint256 fullGroups = data.length / 3;
        uint256 remainder = data.length % 3;
        uint256 encodedLen = fullGroups * 4;
        if (remainder == 1) {
            encodedLen += 2;
        } else if (remainder == 2) {
            encodedLen += 3;
        }

        bytes memory out = new bytes(encodedLen);
        uint256 inPtr = 0;
        uint256 outPtr = 0;

        for (uint256 i = 0; i < fullGroups; i++) {
            uint256 chunk = (uint256(uint8(data[inPtr])) << 16) | (uint256(uint8(data[inPtr + 1])) << 8)
                | uint256(uint8(data[inPtr + 2]));

            out[outPtr] = BASE64URL_TABLE[(chunk >> 18) & 0x3f];
            out[outPtr + 1] = BASE64URL_TABLE[(chunk >> 12) & 0x3f];
            out[outPtr + 2] = BASE64URL_TABLE[(chunk >> 6) & 0x3f];
            out[outPtr + 3] = BASE64URL_TABLE[chunk & 0x3f];

            inPtr += 3;
            outPtr += 4;
        }

        if (remainder == 1) {
            uint256 chunk = uint256(uint8(data[inPtr])) << 16;
            out[outPtr] = BASE64URL_TABLE[(chunk >> 18) & 0x3f];
            out[outPtr + 1] = BASE64URL_TABLE[(chunk >> 12) & 0x3f];
        } else if (remainder == 2) {
            uint256 chunk =
                (uint256(uint8(data[inPtr])) << 16) | (uint256(uint8(data[inPtr + 1])) << 8);
            out[outPtr] = BASE64URL_TABLE[(chunk >> 18) & 0x3f];
            out[outPtr + 1] = BASE64URL_TABLE[(chunk >> 12) & 0x3f];
            out[outPtr + 2] = BASE64URL_TABLE[(chunk >> 6) & 0x3f];
        }

        return string(out);
    }
}
