// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice P-256 서명 검증 인터페이스
/// @dev signature = r||s (64바이트), pubkey = x||y (64바이트)
interface IP256Verifier {
    function verify(bytes32 message, bytes calldata signature, bytes calldata pubkey) external view returns (bool);
}