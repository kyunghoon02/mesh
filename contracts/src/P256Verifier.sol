// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IP256Verifier} from "./interfaces/IP256Verifier.sol";

/// @title P256Verifier
/// @notice EIP-7212 스타일 precompile 호출 래퍼
/// @dev 입력 포맷: msgHash(32) || r(32) || s(32) || x(32) || y(32)
contract P256Verifier is IP256Verifier {
    address public precompile;

    constructor(address precompile_) {
        precompile = precompile_;
    }

    function verify(bytes32 message, bytes calldata signature, bytes calldata pubkey)
        external
        view
        override
        returns (bool)
    {
        if (precompile == address(0)) return false;
        if (signature.length != 64) return false;
        if (pubkey.length != 64) return false;

        bytes32 r;
        bytes32 s;
        bytes32 x;
        bytes32 y;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            x := calldataload(pubkey.offset)
            y := calldataload(add(pubkey.offset, 32))
        }

        bytes memory input = abi.encodePacked(message, r, s, x, y);
        (bool ok, bytes memory out) = precompile.staticcall(input);
        if (!ok || out.length < 32) return false;
        return abi.decode(out, (uint256)) == 1;
    }
}
