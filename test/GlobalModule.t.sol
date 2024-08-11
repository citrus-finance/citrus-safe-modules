// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";

import {ISafe} from "../src/interfaces/ISafe.sol";
import {ISafeProxyFactory} from "../src/interfaces/ISafeProxyFactory.sol";

import {ModuleSetup} from "../src/ModuleSetup.sol";
import {GlobalModule, ExecutionFailed} from "../src/GlobalModule.sol";

contract StorageSetter {
    function setStorage(bytes3 data) public {
        bytes32 slot = 0x4242424242424242424242424242424242424242424242424242424242424242;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, data)
        }
    }
}

contract Reverter {
    function revert() public pure {
        require(false, "Shit happens");
    }
}

contract ERC1271 {
    function isValidSignature(bytes memory, bytes memory) public pure returns (bytes4 magicValue) {
        return 0x20c13b0b;
    }
}

error InvalidFEOpcode();

contract GlobalModuleTest is Test {
    ISafe public safeSingleton = ISafe(0x41675C099F32341bf84BFc5382aF534df5C7461a);
    ISafeProxyFactory public safeProxyFactory = ISafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);

    StorageSetter public storageSetter;
    Reverter public reverter;
    ERC1271 public signer;

    ModuleSetup public moduleSetup;
    GlobalModule public module;

    function setUp() public {
        vm.createSelectFork("https://rpc.sepolia.org");

        storageSetter = new StorageSetter();
        reverter = new Reverter();
        signer = new ERC1271();

        moduleSetup = new ModuleSetup();
        module = new GlobalModule();
    }

    function createSafe(address[] memory owners) public returns (ISafe) {
        bytes memory initializer = abi.encodeWithSelector(
            ISafe.setup.selector,
            owners,
            owners.length,
            address(moduleSetup),
            abi.encodeWithSelector(moduleSetup.enableModules.selector, getAddressArray(address(module))),
            address(0),
            address(0),
            0,
            address(0)
        );

        return safeProxyFactory.createProxyWithNonce(address(safeSingleton), initializer, 0);
    }

    function testCall() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user1, txHash);

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testRevertForFailedCall() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(reverter.revert.selector);

        bytes32 txHash = module.getTransactionHash(safe, address(reverter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user1, txHash);

        vm.expectRevert(ExecutionFailed.selector);
        module.execTransaction(safe, address(reverter), 0, data, 0, concatenateBytesArray(signatures));
    }

    function testDelegateCall() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 1, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user1, txHash);

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 1, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testRevertForFailedDelegateCall() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(reverter.revert.selector);

        bytes32 txHash = module.getTransactionHash(safe, address(reverter), 0, data, 1, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user1, txHash);

        vm.expectRevert(ExecutionFailed.selector);
        module.execTransaction(safe, address(reverter), 0, data, 1, concatenateBytesArray(signatures));
    }

    function testRevertOnUnknownOperation() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 2, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user1, txHash);

        vm.expectRevert();
        module.execTransaction(safe, address(storageSetter), 0, data, 2, concatenateBytesArray(signatures));
    }

    function testRevertIfNotOwner() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user2, txHash);

        vm.expectRevert("GS026");
        module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));
    }

    function testRequiredSignatureThresholdNotMet() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");

        ISafe safe = createSafe(getAddressArray(user1.addr, user2.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP712(user2, txHash);

        vm.expectRevert("GS020");
        module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));
    }

    function testSameOwnerCannotSignTwice() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");

        ISafe safe = createSafe(getAddressArray(user1.addr, user2.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signEIP712(user1, txHash);
        signatures[1] = signEIP712(user1, txHash);

        vm.expectRevert("GS026");
        module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));
    }

    function testApproveHash() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signApproveHash(user1, safe, txHash);

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testSignedEthereumMessage() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");

        ISafe safe = createSafe(getAddressArray(user1.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEthereumMessage(user1, txHash);

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testContractSignature() public {
        ISafe safe = createSafe(getAddressArray(address(signer)));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signEIP1271(address(signer), txHash);

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testAllSignatureType() public {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");
        Vm.Wallet memory user3 = vm.createWallet("user3");

        ISafe safe = createSafe(getAddressArray(user1.addr, user2.addr, user3.addr));

        bytes memory data = abi.encodeWithSelector(storageSetter.setStorage.selector, bytes3(0xbaddad));

        bytes32 txHash = module.getTransactionHash(safe, address(storageSetter), 0, data, 0, 0);

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signEIP712(user1, txHash);
        signatures[1] = signApproveHash(user2, safe, txHash);
        signatures[2] = signEthereumMessage(user3, txHash);
        // TODO: add signEIP1271

        bool success =
            module.execTransaction(safe, address(storageSetter), 0, data, 0, concatenateBytesArray(signatures));

        assertTrue(success);

        assertEq(
            vm.load(address(storageSetter), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0xbaddad0000000000000000000000000000000000000000000000000000000000
        );

        assertEq(
            vm.load(address(safe), 0x4242424242424242424242424242424242424242424242424242424242424242),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    // Sign functions

    function signEIP712(Vm.Wallet memory wallet, bytes32 digest) public returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, digest);

        signature = abi.encodePacked(r, s, v);
    }

    function signApproveHash(Vm.Wallet memory wallet, ISafe safe, bytes32 digest)
        public
        returns (bytes memory signature)
    {
        vm.prank(wallet.addr);
        safe.approveHash(digest);

        uint8 v = 1;
        bytes32 r = bytes32(uint256(uint160(wallet.addr)));
        bytes32 s = 0;

        signature = abi.encodePacked(r, s, v);
    }

    function signEthereumMessage(Vm.Wallet memory wallet, bytes32 digest) public returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(wallet, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)));

        signature = abi.encodePacked(r, s, v + 4);
    }

    function signEIP1271(address signer_, bytes32) public pure returns (bytes memory signature) {
        uint8 v = 0;
        bytes32 r = bytes32(uint256(uint160(signer_)));
        bytes memory s =
            hex"00000000000000000000000000000000000000000000000000000000000000410000000000000000000000000000000000000000000000000000000000000000";

        signature = abi.encodePacked(r, s, v);
    }

    // Utils functions

    function getAddressArray(address addr1) public pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = addr1;
    }

    function getAddressArray(address addr1, address addr2) public pure returns (address[] memory arr) {
        arr = new address[](2);
        arr[0] = addr1;
        arr[1] = addr2;
    }

    function getAddressArray(address addr1, address addr2, address addr3) public pure returns (address[] memory arr) {
        arr = new address[](3);
        arr[0] = addr1;
        arr[1] = addr2;
        arr[2] = addr3;
    }

    function concatenateBytesArray(bytes[] memory _bytesArray) public pure returns (bytes memory) {
        bytes memory result;
        for (uint256 i = 0; i < _bytesArray.length; i++) {
            result = abi.encodePacked(result, _bytesArray[i]);
        }
        return result;
    }
}
