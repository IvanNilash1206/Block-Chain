// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VeritasPack PackageRegistry
/// @notice Anchors product lifecycle commitments after off-chain secure-tag verification.
/// @dev The contract cannot verify RFID HMACs: authorized inspectors attest to that result.
contract PackageRegistry {
    error Unauthorized();
    error AlreadyExists();
    error UnknownProduct();
    error InvalidCounter();
    error Revoked();
    error ZeroValue();

    address public owner;
    mapping(address => bool) public manufacturers;
    mapping(address => bool) public inspectors;

    struct Package {
        bytes32 batchCommitment;
        bytes32 latestEventHash;
        uint64 lastCounter;
        bool tampered;
        bool revoked;
        bool exists;
    }
    mapping(bytes32 => Package) private packages;

    event RoleUpdated(address indexed account, bool manufacturer, bool inspector);
    event PackageRegistered(bytes32 indexed packageId, bytes32 indexed batchCommitment, bytes32 eventHash);
    event ScanAnchored(bytes32 indexed packageId, uint64 counter, bool tampered, bytes32 proofDigest, bytes32 eventHash);
    event PackageRevoked(bytes32 indexed packageId, bytes32 eventHash);

    constructor() {
        owner = msg.sender;
        manufacturers[msg.sender] = true;
        inspectors[msg.sender] = true;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function setRoles(address account, bool manufacturer, bool inspector) external onlyOwner {
        if (account == address(0)) revert ZeroValue();
        manufacturers[account] = manufacturer;
        inspectors[account] = inspector;
        emit RoleUpdated(account, manufacturer, inspector);
    }

    function register(bytes32 packageId, bytes32 batchCommitment, bytes32 eventHash) external {
        if (!manufacturers[msg.sender]) revert Unauthorized();
        if (packageId == bytes32(0) || batchCommitment == bytes32(0) || eventHash == bytes32(0)) revert ZeroValue();
        if (packages[packageId].exists) revert AlreadyExists();
        packages[packageId] = Package(batchCommitment, eventHash, 0, false, false, true);
        emit PackageRegistered(packageId, batchCommitment, eventHash);
    }

    function anchorScan(bytes32 packageId, uint64 counter, bool tamper,
                        bytes32 proofDigest, bytes32 eventHash) external {
        if (!inspectors[msg.sender]) revert Unauthorized();
        Package storage item = packages[packageId];
        if (!item.exists) revert UnknownProduct();
        if (item.revoked) revert Revoked();
        if (counter <= item.lastCounter) revert InvalidCounter();
        if (proofDigest == bytes32(0) || eventHash == bytes32(0)) revert ZeroValue();
        item.lastCounter = counter;
        item.tampered = item.tampered || tamper;
        item.latestEventHash = eventHash;
        emit ScanAnchored(packageId, counter, item.tampered, proofDigest, eventHash);
    }

    function revoke(bytes32 packageId, bytes32 eventHash) external {
        if (!manufacturers[msg.sender]) revert Unauthorized();
        Package storage item = packages[packageId];
        if (!item.exists) revert UnknownProduct();
        if (eventHash == bytes32(0)) revert ZeroValue();
        item.revoked = true;
        item.latestEventHash = eventHash;
        emit PackageRevoked(packageId, eventHash);
    }

    function getPackage(bytes32 packageId) external view returns (Package memory) {
        if (!packages[packageId].exists) revert UnknownProduct();
        return packages[packageId];
    }
}
