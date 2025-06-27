pragma solidity ^0.8.20;

contract DIDRegistry {
    event DIDRegistered(string did, address controller, string ipfsCid);
    event VCRevoked(string vcId);

    struct DIDRecord {
        address controller;
        string ipfsCid;
    }

    mapping(string => DIDRecord) private dids;
    mapping(string => bool) private revokedVCs;
    mapping(string => string) private vcIssuer;

    modifier onlyController(string memory did) {
        require(msg.sender == dids[did].controller, "Not DID controller");
        _;
    }

    function registerDID(string memory did, string memory ipfsCid) public {
        require(dids[did].controller == address(0), "DID already registered");
        dids[did] = DIDRecord(msg.sender, ipfsCid);
        emit DIDRegistered(did, msg.sender, ipfsCid);
    }

    function getDIDCID(string memory did) public view returns (string memory) {
        return dids[did].ipfsCid;
    }

    function getDIDController(string memory did) public view returns (address) {
        return dids[did].controller;
    }

    function recordVC(string memory vcId, string memory did) public onlyController(did) {
        require(bytes(vcIssuer[vcId]).length == 0, "VC already recorded");
        vcIssuer[vcId] = did;
    }

    function revokeVC(string memory vcId) public {
        string memory did = vcIssuer[vcId];
        require(bytes(did).length != 0, "VC not recorded");
        require(msg.sender == dids[did].controller, "Not DID controller");
        revokedVCs[vcId] = true;
        emit VCRevoked(vcId);
    }

    function isVCRevoked(string memory vcId) public view returns (bool) {
        return revokedVCs[vcId];
    }

    function getVCIssuer(string memory vcId) public view returns (string memory) {
        return vcIssuer[vcId];
    }
}
