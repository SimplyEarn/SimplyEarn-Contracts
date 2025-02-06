// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISeERC20} from "./interfaces/ISeERC20.sol";

contract SimplyEarnStake is PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using SafeERC20 for ISeERC20;


    struct StakeInfo {
        uint256 stakingAmount;
        uint256 unStakedAmount;
        uint256 reward;
    }


    mapping(address user => StakeInfo info) public stakeInfos;
    mapping(address signer => bool active) public signers;
    mapping(uint256 msgId => bool status) public claimReceipts;

    address public USDse;
    uint256 public STAKING_AMOUNT;
    uint256 public TOTAL_CLAIMED_REWARD;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 constant public ZOOM = 10_000;

    event Stake(
        address indexed user,
        uint256 indexed amount,
        uint256 indexed stakingAmount,
        uint256 time
    );

    event UnStake(
        address indexed user,
        uint256 indexed amount,
        uint256 indexed stakingAmount,
        uint256 time
    );

    event ClaimYield(
        uint256 indexed id,
        address indexed user,
        uint256 indexed amount,
        uint256 stakingAmount
    );

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {}

    receive() external payable {}

    function initialize(
        address _admin,
        address _USDse,
        address _signer
    ) external initializer {
        require(_admin != address(0), '_admin Zero Address');
        require(_USDse != address(0), '_USDse Zero Address');
        require(_signer != address(0), '_signer Zero Address');

        signers[_signer] = true;
        USDse = _USDse;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
    }


    function setUSDse(address _USDse) external onlyRole(ADMIN_ROLE) {
        require(_USDse != address(0), '_USDse Zero Address ');
        USDse = _USDse;
    }

    function withdrawNative(address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        payable(_to).transfer(_amount);
    }

    function withdrawToken(address _token, address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        ISeERC20(_token).safeTransfer(_to, _amount);
    }


    function stake(uint256 _amount) external whenNotPaused nonReentrant {
        require(_amount > 0, '_amount Zero');
        StakeInfo storage stakeInfo = stakeInfos[msg.sender];
        stakeInfo.stakingAmount += _amount;
        STAKING_AMOUNT += _amount;
        ISeERC20(USDse).safeTransferFrom(msg.sender, address(this), _amount);

        emit Stake(msg.sender, _amount, stakeInfo.stakingAmount, block.timestamp);
    }

    function unStake(uint256 _amount) external whenNotPaused nonReentrant {
        require(_amount > 0, '_amount Zero');
        StakeInfo storage stakeInfo = stakeInfos[msg.sender];
        require(stakeInfo.stakingAmount >= _amount, 'Invalid Amount');

        stakeInfo.stakingAmount -= _amount;
        stakeInfo.unStakedAmount += _amount;
        STAKING_AMOUNT -= _amount;

        ISeERC20(USDse).safeTransfer(msg.sender, _amount);
        emit UnStake(msg.sender, _amount, stakeInfo.stakingAmount, block.timestamp);
    }


    function claim(
        uint256 _msgId,
        uint256 _amount,
        bytes calldata _sig
    ) external nonReentrant whenNotPaused {
        address recipient = msg.sender;
        require(claimReceipts[_msgId] == false, 'Claimed');
        require(_amount > 0, 'Invalid Amount');
        require(USDse != address(0), 'REWARD_TOKEN Zero Address');

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            recipient,
            _amount,
            address(this)
        ));
        require(_verifySignature(data, _sig), 'Invalid Signature');

        claimReceipts[_msgId] = true;
        stakeInfos[recipient].reward += _amount;
        TOTAL_CLAIMED_REWARD += _amount;

        require(ISeERC20(USDse).balanceOf(address(this)) >= _amount + STAKING_AMOUNT, 'Insufficient Balance');
        ISeERC20(USDse).safeTransfer(recipient, _amount);

        emit ClaimYield(_msgId, recipient, _amount, stakeInfos[recipient].stakingAmount);
    }

    function _verifySignature(bytes32 _data, bytes memory _signature) internal view returns (bool) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _data));
        address signer = _recoverSigner(ethSignedMessageHash, _signature);
        return signers[signer];
    }

    function _recoverSigner(bytes32 ethSignedMessageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function pause() public onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}


