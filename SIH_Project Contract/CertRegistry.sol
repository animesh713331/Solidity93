// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title CertRegistry
 * @dev Manages the immutable registry of verified certificates and records.
 * The contract serves as a tamper-proof ledger for all credentials issued by approved entities.
 */
contract CertRegistry is Ownable {
    // --- State Variables ---
    
    // Mapping from a unique record ID hash to the record details
    mapping(bytes32 => Record) private records;

    // A mapping to register approved issuers (e.g., faculty, departments)
    mapping(address => bool) public isIssuer;

    // --- Data Structures ---
    
    struct Record {
        address issuerAddress;
        bytes32 fileHash;
        uint256 issuedAt;
        bool revoked;
    }

    // --- Events ---
    
    // Emitted when a new record is successfully issued.
    event RecordIssued(
        bytes32 indexed recordIdHash,
        address indexed issuer,
        bytes32 fileHash,
        uint256 issuedAt
    );

    // Emitted when a record is revoked.
    event RecordRevoked(
        bytes32 indexed recordIdHash,
        address indexed revoker,
        uint256 revokedAt
    );

    // --- Constructor ---
    
    /**
     * @dev The contract deployer is set as the initial admin and issuer.
     */
    constructor() Ownable(msg.sender) {
        isIssuer[msg.sender] = true;
    }

    // --- Modifiers ---

    /**
     * @dev Throws if the caller is not a registered issuer.
     */
    modifier onlyIssuer() {
        require(isIssuer[msg.sender], "Only registered issuers can perform this action");
        _;
    }

    // --- Admin Functions (onlyOwner) ---
    
    /**
     * @dev Adds a new address to the list of approved issuers.
     * @param _issuer The address to be added.
     */
    function addIssuer(address _issuer) external onlyOwner {
        require(_issuer != address(0), "Invalid address");
        isIssuer[_issuer] = true;
    }

    /**
     * @dev Removes an address from the list of approved issuers.
     * @param _issuer The address to be removed.
     */
    function removeIssuer(address _issuer) external onlyOwner {
        require(_issuer != address(0), "Invalid address");
        isIssuer[_issuer] = false;
    }

    // --- Core Functions ---
    
    /**
     * @notice Issues a new record and stores it on the blockchain.
     * @dev The recordIdHash is a unique identifier for the record (e.g., a hash of the off-chain ID).
     * @param _recordIdHash The unique hash of the off-chain record ID.
     * @param _fileHash The hash of the file (e.g., PDF) being certified.
     */
    function issueRecord(
        bytes32 _recordIdHash,
        bytes32 _fileHash
    ) external onlyIssuer {
        require(records[_recordIdHash].issuedAt == 0, "Record already exists");

        records[_recordIdHash] = Record({
            issuerAddress: msg.sender,
            fileHash: _fileHash,
            issuedAt: block.timestamp,
            revoked: false
        });

        emit RecordIssued(_recordIdHash, msg.sender, _fileHash, block.timestamp);
    }

    /**
     * @notice Revokes an existing record.
     * @dev Can only be called by the original issuer or the contract owner.
     * @param _recordIdHash The unique hash of the off-chain record ID.
     */
    function revokeRecord(bytes32 _recordIdHash) external onlyIssuer {
        Record storage r = records[_recordIdHash];
        require(r.issuedAt != 0, "Record does not exist");
        require(r.issuerAddress == msg.sender || owner() == msg.sender, "Not authorized to revoke");
        require(!r.revoked, "Record is already revoked");

        r.revoked = true;
        emit RecordRevoked(_recordIdHash, msg.sender, block.timestamp);
    }

    // --- View Functions ---
    
    function getRecord(bytes32 _recordIdHash) external view returns (
        address issuer,
        bytes32 fileHash,
        uint256 issuedAt,
        bool revoked
    ) {
        Record storage r = records[_recordIdHash];
        return (r.issuerAddress, r.fileHash, r.issuedAt, r.revoked);
    }

    /**
     * @notice Verifies a record's existence and authenticity.
     * @dev This function is critical for off-chain verification processes.
     * @param _recordIdHash The unique hash of the off-chain record ID.
     * @param _fileHash The hash of the file to verify.
     * @return A boolean indicating if the record is valid, and a boolean if it has been revoked.
     */
    function verifyRecord(bytes32 _recordIdHash, bytes32 _fileHash) external view returns (bool, bool) {
        Record storage r = records[_recordIdHash];
        // Check for existence and that the hashes match
        bool isAuthentic = (r.issuedAt != 0 && r.fileHash == _fileHash);
        return (isAuthentic, r.revoked);
    }
}