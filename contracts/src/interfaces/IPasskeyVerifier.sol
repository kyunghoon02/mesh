// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Passkey(WebAuthn) 서명 검증 인터페이스
/// @dev 실제 검증 로직은 외부 Verifier 컨트랙트에서 처리
interface IPasskeyVerifier {
    function verify(
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes calldata signature,
        bytes calldata pubkey,
        bytes32 expectedChallenge
    ) external view returns (bool);
}