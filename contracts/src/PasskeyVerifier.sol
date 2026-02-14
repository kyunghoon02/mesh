// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPasskeyVerifier} from "./interfaces/IPasskeyVerifier.sol";
import {IP256Verifier} from "./interfaces/IP256Verifier.sol";

/// @title PasskeyVerifier
/// @notice WebAuthn 서명 검증을 외부 P-256 Verifier에 위임
/// @dev challenge(JSON 파싱)는 현재 구현하지 않음
contract PasskeyVerifier is IPasskeyVerifier {
    address public p256Verifier;

    event VerifierUpdated(address verifier);

    constructor(address verifier) {
        p256Verifier = verifier;
        emit VerifierUpdated(verifier);
    }

    /// @notice P-256 Verifier 주소 갱신
    function setP256Verifier(address verifier) external {
        p256Verifier = verifier;
        emit VerifierUpdated(verifier);
    }

    function verify(
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes calldata signature,
        bytes calldata pubkey,
        bytes32 /* expectedChallenge */
    ) external view override returns (bool) {
        if (p256Verifier == address(0)) {
            return false;
        }

        // WebAuthn 서명 입력: SHA256(authenticatorData || SHA256(clientDataJSON))
        bytes32 clientHash = sha256(clientDataJSON);
        bytes32 msgHash = sha256(abi.encodePacked(authenticatorData, clientHash));

        return IP256Verifier(p256Verifier).verify(msgHash, signature, pubkey);
    }
}