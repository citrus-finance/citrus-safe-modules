// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.0 <0.9.0;

import {ISafe} from "./interfaces/ISafe.sol";

error ExecutionFailed(address safe);
error InvalidNonce(address safe, uint256 currentNonce, uint256 invalidNonce);

/*
* @title GlobalModule
* @author Citrus
* @notice Safe Module allowing the same operation on safes accross multiple chains
* without having to sign multiple times.
*/
contract GlobalModule {
    // keccak256(
    //     "EIP712Domain(address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;

    // keccak256(
    //     "SafeTx(address safe, address to,uint256 value,bytes32 data,uint8 operation,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0x0665fbc39e688daa835492cf4e62db9cc70e492a81eaeca0edc5df667def7cc6;

    // nonce for each safes to prevent replay attack
    mapping(ISafe safe => uint256 nonce) public nonces;

    /**
     * @notice Executes a `operation` {0: Call, 1: DelegateCall}} transaction to `to` with `value` (Native Currency)
     * @dev This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      It is the responsibility of the caller to perform such checks.
     * @param safe The safe the transaction will be executed on
     * @param to Destination address of Safe transaction.
     * @param value Ether value of Safe transaction.
     * @param data Data payload of Safe transaction.
     * @param operation Operation type of Safe transaction.
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @return success Boolean indicating transaction's success.
     */
    function execTransaction(
        ISafe safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes memory signatures
    ) external virtual returns (bool) {
        bytes32 txHash;
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            uint256 nonce = nonces[safe];
            bytes memory txHashData = encodeTransactionData(
                safe,
                // Transaction info
                to,
                value,
                data,
                operation,
                // Signature info
                nonce
            );
            // Increase nonce and execute transaction.
            nonces[safe]++;
            txHash = keccak256(txHashData);
            safe.checkSignatures(txHash, txHashData, signatures);
        }

        // If execution fails, the whole transaction should fail
        // so that the nonce is not updated.
        // @dev If that transaction cannot be executed, use skipNonce.
        if (!safe.execTransactionFromModule(to, value, data, operation)) {
            revert ExecutionFailed(address(safe));
        }

        return true;
    }

    /**
     * @dev Returns the domain separator for the safe contract, as defined in the EIP-712 standard.
     * @return bytes32 The domain separator hash.
     */
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, address(this)));
    }

    /**
     * @notice Returns the pre-image of the transaction hash (see getTransactionHash).
     * @param safe The safe the transaction will be executed on
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @param _nonce Transaction nonce.
     * @return Transaction hash bytes.
     */
    function encodeTransactionData(
        ISafe safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash =
            keccak256(abi.encode(SAFE_TX_TYPEHASH, safe, to, value, keccak256(data), operation, _nonce));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }

    /**
     * @notice Returns transaction hash to be signed by owners.
     * @param safe The safe the transaction will be executed on
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @param _nonce Transaction nonce.
     * @return Transaction hash.
     */
    function getTransactionHash(
        ISafe safe,
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 _nonce
    ) external view returns (bytes32) {
        return keccak256(encodeTransactionData(safe, to, value, data, operation, _nonce));
    }

    /**
     * @notice Skip the nonce
     * @dev allows skipping a nonce if for some reason the associated transaction fails
     * @param nonceToSkip The nonce to skip, it needs to be the current nonce
     *                     to prevent front-running attack
     */
    function skipNonce(uint256 nonceToSkip) external {
        if (nonceToSkip != nonces[ISafe(msg.sender)]) {
            revert InvalidNonce(msg.sender, nonces[ISafe(msg.sender)], nonceToSkip);
        }

        nonces[ISafe(msg.sender)]++;
    }
}
