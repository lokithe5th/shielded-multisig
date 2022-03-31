// SPDX-License-Identifier: MIT

//  Off-chain signature gathering multisig that streams funds - @austingriffith
//
// started from 🏗 scaffold-eth - meta-multi-sig-wallet example https://github.com/austintgriffith/scaffold-eth/tree/meta-multi-sig
//    (off-chain signature based multi-sig)
//  added a very simple "shielding" mechanism to allow funders to fund the MultiSig, but have no control over the funds.
//  Once the MultiSig has initiated the claims process, funders can claim their funds + profits back from the MultiSig
//  This becomes interesting in cases where the multisig is owned by a non-human participant.
//  The benefit being (depending on local jurisdictions) that taxes only accrue on the profits when claimed @lourenslinde 

//  TL;DR A tax-efficient investment vehicle for on-chain activities. 

pragma solidity >=0.6.0 <0.9.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/cryptography/ECDSA.sol";

contract ShieldedMetaMultiSigWallet {
    using ECDSA for bytes32;

    event Deposit(address indexed sender, uint amount, uint balance);
    event ExecuteTransaction( address indexed owner, address payable to, uint256 value, bytes data, uint256 nonce, bytes32 hash, bytes result);
    event Owner( address indexed owner, bool added);

    mapping(address => bool) public isOwner;
    uint public signaturesRequired;
    uint public nonce;
    uint public chainId;

    constructor(uint256 _chainId, address[] memory _owners, uint _signaturesRequired) public {
        require(_signaturesRequired>0,"constructor: must be non-zero sigs required");
        signaturesRequired = _signaturesRequired;
        for (uint i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner!=address(0), "constructor: zero address");
            require(!isOwner[owner], "constructor: owner not unique");
            isOwner[owner] = true;
            emit Owner(owner,isOwner[owner]);
        }
        chainId=_chainId;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "Not Self");
        _;
    }

    function addSigner(address newSigner, uint256 newSignaturesRequired) public onlySelf {
        require(newSigner!=address(0), "addSigner: zero address");
        require(!isOwner[newSigner], "addSigner: owner not unique");
        require(newSignaturesRequired>0,"addSigner: must be non-zero sigs required");
        isOwner[newSigner] = true;
        signaturesRequired = newSignaturesRequired;
        emit Owner(newSigner,isOwner[newSigner]);
    }

    function removeSigner(address oldSigner, uint256 newSignaturesRequired) public onlySelf {
        require(isOwner[oldSigner], "removeSigner: not owner");
        require(newSignaturesRequired>0,"removeSigner: must be non-zero sigs required");
        isOwner[oldSigner] = false;
        signaturesRequired = newSignaturesRequired;
        emit Owner(oldSigner,isOwner[oldSigner]);
    }

    function updateSignaturesRequired(uint256 newSignaturesRequired) public onlySelf {
        require(newSignaturesRequired>0,"updateSignaturesRequired: must be non-zero sigs required");
        signaturesRequired = newSignaturesRequired;
    }

    function getTransactionHash( uint256 _nonce, address to, uint256 value, bytes memory data ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this),chainId,_nonce,to,value,data));
    }

    function executeTransaction( address payable to, uint256 value, bytes memory data, bytes[] memory signatures)
        public
        returns (bytes memory)
    {
        require(isOwner[msg.sender], "executeTransaction: only owners can execute");
        bytes32 _hash =  getTransactionHash(nonce, to, value, data);
        nonce++;
        uint256 validSignatures;
        address duplicateGuard;
        for (uint i = 0; i < signatures.length; i++) {
            address recovered = recover(_hash,signatures[i]);
            require(recovered>duplicateGuard, "executeTransaction: duplicate or unordered signatures");
            duplicateGuard = recovered;
            if(isOwner[recovered]){
              validSignatures++;
            }
        }

        require(validSignatures>=signaturesRequired, "executeTransaction: not enough valid signatures");

        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "executeTransaction: tx failed");

        emit ExecuteTransaction(msg.sender, to, value, data, nonce-1, _hash, result);
        return result;
    }

    function recover(bytes32 _hash, bytes memory _signature) public pure returns (address) {
        return _hash.toEthSignedMessageHash().recover(_signature);
    }

    // Trust Functionality
    mapping(address => uint256) public balances;
    bool public isClaimable;
    uint256 public claimableFunds;
    uint256 public fundsClaimed;
    uint256 public claimWindow;
    uint8 public fee;
    uint256 public initTime;

    event StartClaimProcess(address initiator, uint256 startDate, uint256 endDate);
    event ClaimsOpen(address initiator);
    event Claim(address funder, uint256 amount);

    /// custom:receive The receive function should take any ether deposited and add it to the sender's balance
    receive() payable external {
        emit Deposit(msg.sender, msg.value, address(this).balance);
        if (!isClaimable && !(claimWindow > 0)) {
          balances[msg.sender] += msg.value;
          claimableFunds += msg.value;
        }
    }
 
    /// @notice Sets the claim window
    /// @dev The MultiSig has _claimWindow seconds to return the funds to the MultiSig address before claims can be made against contributed eth
    /// @return uint256 Date in future when claim window expires
    /// @param _claimWindow: uint256 value representing the amount of time the claim window must be open.
    function initClaimWindow(uint256 _claimWindow) public onlySelf returns(uint256) {
      require(!isClaimable, "Claim window already initialized");
      claimWindow = _claimWindow + block.timestamp;
      emit StartClaimProcess(msg.sender, block.timestamp, _claimWindow);
      return block.timestamp + _claimWindow;
    }

    /// @notice Called by any address to open Claims for funders
    /// @dev Sets the isClaimable variable to "true" and records the initTime value
    function initClaims() public returns(bool) {
      require(claimWindow < block.timestamp, "Pre-claim window is still open");
      isClaimable = true;
      initTime = block.timestamp;
      emit ClaimsOpen(msg.sender);
      return true;
    }

    modifier onlyFunder() {
      require(balances[msg.sender] > 0,"Not a funder");
      _;
    }

    /// @notice Returns the MultiSig funds
    function totalFunds() public view returns(uint256) {
      return address(this).balance;
    }

    /// @notice Function for claiming portion of funds from wallet
    /// @dev Requires the address where funds must be sent
    /// @param _to Address where funds must be sent
    function claim(address payable _to) public onlyFunder returns(uint256) {
      require(isClaimable, "Funds not yet claimable");
      require(initTime + claimWindow > block.timestamp, "Claim window expired");
      uint256 _funds = _determineFunds();
      (bool sent, bytes memory data) = _to.call{value: _funds}("");
      require(sent, "Failed to send Ether");
      emit Claim(msg.sender, _funds);
      fundsClaimed += _funds;
      return _funds;
    }

    /// internal functions
    /// @notice Determine the funds that must be aportioned to the msg.sender
    /// @return return the return variables of a contract’s function state variable
    function _determineFunds() internal view returns(uint256){
      return (balances[msg.sender]/claimableFunds)*(address(this).balance); 
    }

}
