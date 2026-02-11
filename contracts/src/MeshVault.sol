// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MeshVault - 최소 스켈레톤 SCA
/// @notice EOA 소유자 + Passkey(P-256) 공개키 보관 + ERC-1271 검증
contract MeshVault {
    // ERC-1271 magic value
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    address public immutable owner;
    bytes public passkeyPubkey; // WebAuthn에서 추출한 P-256 공개키(raw/COSE/압축 등 형식은 상위 레이어에서 정의)

    event PasskeyUpdated(bytes newPubkey);

    constructor(address owner_, bytes memory passkeyPubkey_) {
        require(owner_ != address(0), "owner=0");
        owner = owner_;
        passkeyPubkey = passkeyPubkey_;
    }

    /// @notice Passkey 공개키 갱신 (EOA 소유자만)
    function setPasskey(bytes calldata newPubkey) external {
        require(msg.sender == owner, "not owner");
        passkeyPubkey = newPubkey;
        emit PasskeyUpdated(newPubkey);
    }

    /// @notice ERC-1271 메시지 서명 검증 (EOA 서명 기준)
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        address signer = _recover(hash, signature);
        if (signer == owner) {
            return MAGICVALUE;
        }
        return 0xffffffff;
    }

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
