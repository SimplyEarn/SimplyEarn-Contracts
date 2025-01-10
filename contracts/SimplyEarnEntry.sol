// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISeERC20} from "./interfaces/ISeERC20.sol";

contract SimplyEarnEntry is PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using SafeERC20 for ISeERC20;

    struct DepositReceipt {
        address to;
        address srcToken;
        uint256 srcAmount;
        uint256 dstAmount;
    }

    mapping(address signer => bool active) public signers;
    mapping(address token => bool active) public tokens;
    mapping(uint256 msgId => DepositReceipt receipt) public depositReceipts;
    address public TREASURY;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    event Deposit(
        uint256 indexed msgId,
        address indexed to,
        address srcToken,
        uint256 srcAmount,
        uint256 dstAmount
    );


    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {}

    receive() external payable {}

    function initialize(
        address _admin,
        address _signer,
        address _treasury,
        address[] calldata _initTokens
    ) external initializer {
        require(_admin != address(0), '_admin Zero Address');
        require(_signer != address(0), '_signer Zero Address');
        require(_treasury != address(0), '_treasury Zero Address');

        signers[_signer] = true;
        TREASURY = _treasury;

        require(_initTokens.length > 0, 'Empty _initTokens');
        for (uint256 i = 0; i < _initTokens.length; i++) {
            require(_initTokens[i] != address(0), 'Tokens Zero');
            tokens[_initTokens[i]] = true;
        }

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);

        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
    }

    function setSigner(address _signer, bool _active) external onlyRole(ADMIN_ROLE) {
        require(_signer != address(0), '_signer Zero Address');
        signers[_signer] = _active;
    }

    function setToken(address _token, bool _active) external onlyRole(ADMIN_ROLE) {
        require(_token != address(0), '_token Zero Address');
        tokens[_token] = _active;
    }

    function setTreasury(address _treasury) external onlyRole(ADMIN_ROLE) {
        require(_treasury != address(0), '_USDse Zero Address ');
        TREASURY = _treasury;
    }

    function withdrawNative(address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        payable(_to).transfer(_amount);
    }

    function withdrawToken(address _token, address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        ISeERC20(_token).safeTransfer(_to, _amount);
    }

    function deposit(
        uint256 _msgId,
        address _srcToken,
        uint256 _srcAmount,
        bytes calldata _sig
    ) external whenNotPaused nonReentrant {
        require(TREASURY != address(0), 'TREASURY Zero');
        require(depositReceipts[_msgId].to == address(0), 'deposited');
        require(tokens[_srcToken], '_srcToken Not Supported');
        require(_srcAmount > 0, '_srcAmount Zero');

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            msg.sender,
            _srcToken,
            _srcAmount,
            chainId,
            address(this)));
        require(_verifySignature(data, _sig), 'Invalid Signature');


        uint256 amountOut = _convertAmountTo18Decimals(_srcToken, _srcAmount);
        require(amountOut > 0, 'amountOut Zero');
        depositReceipts[_msgId] = DepositReceipt(
            msg.sender,
            _srcToken,
            _srcAmount,
            amountOut
        );

        ISeERC20(_srcToken).safeTransferFrom(msg.sender, TREASURY, _srcAmount);

        emit Deposit(_msgId, msg.sender, _srcToken, _srcAmount, amountOut);
    }


    function _convertAmountTo18Decimals(address _token, uint256 _amount) internal view returns (uint256) {
        uint tokenDecimals = ISeERC20(_token).decimals();
        require(tokenDecimals <= 18, 'Minting: invalid token decimals');
        if (tokenDecimals >= 18) return _amount;
        return _amount * (10 ** (18 - tokenDecimals));
    }


    function _verifySignature(bytes32 _data, bytes memory _signature) internal view returns (bool) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _data));
        address signer = _recoverSigner(ethSignedMessageHash, _signature);
        return signers[signer];
    }

    function _recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function pause() public onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
