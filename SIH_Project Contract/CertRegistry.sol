// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title CertRegistry
 * @dev This contract manages the immutable registry of verified certificates and records.
 * Access is restricted to designated roles (Admin, Faculty, Department).
 */
contract CertRegistry is AccessControl {
    // --- Roles ---
    // The admin role can manage other roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    // Faculty role for issuing student records
    bytes32 public constant FACULTY_ROLE = keccak256("FACULTY_ROLE");
    
    // Department role for issuing student records and institutional reports (NAAC)
    bytes32 public constant DEPARTMENT_ROLE = keccak256("DEPARTMENT_ROLE");

    // --- State Variables ---
    // Mapping from a unique record ID hash to the record details
    mapping(bytes32 => Record) private records;

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
     * @dev The contract deployer is set as the initial admin.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // --- Role Management (Admin only) ---
    /**
     * @dev Adds a new address to the list of Faculty.
     * @param faculty The address to be added.
     */
    function addFaculty(address faculty) external onlyRole(ADMIN_ROLE) {
        _grantRole(FACULTY_ROLE, faculty);
    }

    /**
     * @dev Adds a new address to the list of Departments.
     * @param department The address to be added.
     */
    function addDepartment(address department) external onlyRole(ADMIN_ROLE) {
        _grantRole(DEPARTMENT_ROLE, department);
    }
    
    // --- Core Functions ---
    /**
     * @notice Issues a new student or general record.
     * @dev Only Faculty or Department can call this function.
     * @param _recordIdHash The unique hash of the off-chain record ID.
     * @param _fileHash The hash of the file (e.g., PDF) being certified.
     */
    function issueRecord(
        bytes32 _recordIdHash,
        bytes32 _fileHash
    ) external {
        // Correctly check for multiple roles using a require statement.
        require(hasRole(FACULTY_ROLE, msg.sender) || hasRole(DEPARTMENT_ROLE, msg.sender), 
            "Caller is not a registered Faculty or Department");
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
     * @notice Issues a new institutional record, such as a NAAC report.
     * @dev Only a registered admin can call this function.
     * @param _recordIdHash The unique hash of the off-chain report ID.
     * @param _fileHash The hash of the PDF report itself.
     */
    function issueInstitutionalRecord(
        bytes32 _recordIdHash,
        bytes32 _fileHash
    ) external onlyRole(ADMIN_ROLE) {
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
     * @dev Can only be called by the original issuer or a contract admin.
     * @param _recordIdHash The unique hash of the off-chain record ID.
     */
    function revokeRecord(bytes32 _recordIdHash) external {
        Record storage r = records[_recordIdHash];
        require(r.issuedAt != 0, "Record does not exist");
        
        // Use hasRole for clear access control check
        require(hasRole(ADMIN_ROLE, msg.sender) || (r.issuerAddress == msg.sender), 
            "Not authorized to revoke");
        require(!r.revoked, "Record is already revoked");

        r.revoked = true;
        emit RecordRevoked(_recordIdHash, msg.sender, block.timestamp);
    }

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
        bool isAuthentic = (r.issuedAt != 0 && r.fileHash == _fileHash);
        return (isAuthentic, r.revoked);
    }
}