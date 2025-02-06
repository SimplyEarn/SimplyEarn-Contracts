// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISeERC20} from "./interfaces/ISeERC20.sol";

contract SimplyEarnFactory is PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using SafeERC20 for ISeERC20;

    enum RedeemStatus {PENDING, DONE, CANCELED}

    struct MintReceipt {
        address to;
        uint256 amountIn;
        uint256 USDseAmount;
        uint256 fee;
    }

    struct RedeemReceipt {
        address to;
        uint256 USDseAmount;
        uint256 amountOut;
        uint256 fee;
        RedeemStatus status;
        uint256 claimTime;
    }

    struct RedeemInfo {
        uint256 USDseAmount;
        uint256 pendingAmount;
        uint256 redeemedAmount;
    }


    mapping(address signer => bool active) public signers;
    mapping(address executor => bool active) public executors;
    mapping(uint256 msgId => MintReceipt receipt) public mintReceipts;
    mapping(uint256 msgId => RedeemReceipt receipt) public redeemReceipts;
    mapping(address user => RedeemInfo info) public redeemInfos;

    address public USDse;
    address public REDEEM_TOKEN;
    uint256 public LOCK_TIME;
    uint256 public PENDING_REDEEM_AMOUNT;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 constant public ZOOM = 10_000;

    event Mint(
        uint256 indexed msgId,
        address indexed to,
        uint256 indexed amountIn,
        uint256 amountOut
    );

    event Redeem(
        uint256 indexed msgId,
        address indexed to,
        address indexed token,
        uint256 amountIn,
        uint256 amountOut
    );

    event WithdrawRedeem(
        uint256 indexed msgId,
        address indexed to,
        address indexed token,
        uint256 amountOut

    );

    event CancelRedeem(
        uint256 indexed msgId,
        address indexed to,
        address indexed token,
        uint256 amountOut
    );

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {}

    receive() external payable {}

    function initialize(
        address _admin,
        address _signer,
        address _executor,
        address _USDse,
        address _redeemToken
    ) external initializer {
        require(_admin != address(0), '_admin Zero Address');
        require(_signer != address(0), '_signer Zero Address');
        require(_executor != address(0), '_executor Zero Address');
        require(_USDse != address(0), '_USDse Zero Address');
        require(_redeemToken != address(0), '_redeemToken Zero Address');

        signers[_signer] = true;
        executors[_executor] = true;
        USDse = _USDse;
        REDEEM_TOKEN = _redeemToken;
        LOCK_TIME = 7 days;


        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
    }

    function setSigner(address _signer, bool _active) external onlyRole(ADMIN_ROLE) {
        require(_signer != address(0), '_signer Zero Address');
        signers[_signer] = _active;
    }


    function setExecutor(address _executor, bool _active) external onlyRole(ADMIN_ROLE) {
        require(_executor != address(0), '_executor Zero Address');
        executors[_executor] = _active;
    }

    function setUSDse(address _USDse) external onlyRole(ADMIN_ROLE) {
        require(_USDse != address(0), '_USDse Zero Address ');
        USDse = _USDse;
    }

    function setRedeemToken(address _redeemToken) external onlyRole(ADMIN_ROLE) {
        require(_redeemToken != address(0), '_redeemToken Zero Address ');
        REDEEM_TOKEN = _redeemToken;
    }

    function withdrawNative(address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        payable(_to).transfer(_amount);
    }

    function withdrawToken(address _token, address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        ISeERC20(_token).safeTransfer(_to, _amount);
    }

    function setLockTime(uint256 _time) external onlyRole(ADMIN_ROLE) {
        LOCK_TIME = _time;
    }

    function mint(
        uint256 _msgId,
        address _to,
        uint256 _amountIn,
        uint256 _fee,
        bytes calldata _sig
    ) external whenNotPaused nonReentrant {
        require(mintReceipts[_msgId].to == address(0), 'minted');
        require(_to != address(0), '_to Zero Address');
        require(_amountIn > 0, '_amount Zero');
        require(executors[msg.sender] || msg.sender == _to, 'Sender Not Valid');
        require(USDse != address(0), 'mint disable');
        require(_fee >= 0 && _fee <= ZOOM, '_fee Invalid');

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            _to,
            _amountIn,
            _fee,
            address(this)));
        require(_verifySignature(data, _sig), 'Invalid Signature');

        uint256 USDseAmount = _calculateMintOut(USDse, _amountIn, _fee);
        require(USDseAmount > 0, 'amountOut Zero');

        mintReceipts[_msgId] = MintReceipt(
            _to,
            _amountIn,
            USDseAmount,
            _fee
        );

        ISeERC20(USDse).mint(_to, USDseAmount);
        emit Mint(_msgId, _to, _amountIn, USDseAmount);
    }


    function redeem(
        uint256 _msgId,
        uint256 _USDseAmount,
        uint256 _fee,
        bytes calldata _sig
    ) external whenNotPaused nonReentrant {
        require(redeemReceipts[_msgId].to == address(0), 'Requested');
        require(_USDseAmount > 0, '_USDseAmount Zero');
        require(_fee >= 0 && _fee <= ZOOM, '_fee Invalid');
        require(USDse != address(0), 'Redeem disable');
        require(REDEEM_TOKEN != address(0), 'Redeem Token Zero');

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            msg.sender,
            _USDseAmount,
            _fee,
            address(this)));
        require(_verifySignature(data, _sig), 'Invalid Signature');

        uint256 amountOut = _calculateRedeemOut(REDEEM_TOKEN, _USDseAmount, _fee);
        require(amountOut > 0, 'amountOut Zero');

        redeemReceipts[_msgId] = RedeemReceipt(
            msg.sender,
            _USDseAmount,
            amountOut,
            _fee,
            RedeemStatus.PENDING,
            block.timestamp + LOCK_TIME
        );

        RedeemInfo storage redeemInfo = redeemInfos[msg.sender];
        redeemInfo.USDseAmount += _USDseAmount;
        redeemInfo.pendingAmount += amountOut;

        PENDING_REDEEM_AMOUNT += amountOut;

        ISeERC20(USDse).safeTransferFrom(msg.sender, address(this), _USDseAmount);
        emit Redeem(_msgId, msg.sender, REDEEM_TOKEN, _USDseAmount, amountOut);
    }

    function withdrawRedeem(
        uint256 _msgId
    ) external whenNotPaused nonReentrant {
        RedeemReceipt storage redeemReceipt = redeemReceipts[_msgId];
        RedeemInfo storage redeemInfo = redeemInfos[redeemReceipt.to];

        require(redeemReceipt.status == RedeemStatus.PENDING, 'Done');
        require(redeemReceipt.to == msg.sender, 'Invalid Owner');
        require(redeemReceipt.claimTime <= block.timestamp, 'Redeem Lock!');
        require(redeemReceipt.amountOut > 0, 'amountOut Zero');

        redeemReceipt.status = RedeemStatus.DONE;

        redeemInfo.pendingAmount -= redeemReceipt.amountOut;
        redeemInfo.redeemedAmount += redeemReceipt.amountOut;

        PENDING_REDEEM_AMOUNT -= redeemReceipt.amountOut;

        ISeERC20(USDse).burn(redeemReceipt.USDseAmount);
        ISeERC20(REDEEM_TOKEN).safeTransfer(redeemReceipt.to, redeemReceipt.amountOut);
        emit WithdrawRedeem(_msgId, redeemReceipt.to, REDEEM_TOKEN, redeemReceipt.amountOut);
    }

    function cancelRedeem(
        uint256 _msgId
    ) external whenNotPaused nonReentrant {
        RedeemReceipt storage redeemReceipt = redeemReceipts[_msgId];
        RedeemInfo storage redeemInfo = redeemInfos[redeemReceipt.to];

        require(redeemReceipt.status == RedeemStatus.PENDING, 'Done');
        require(redeemReceipt.to == msg.sender, 'Invalid Owner');
        require(redeemReceipt.USDseAmount > 0, 'USDseAmount Zero');
        require(redeemReceipt.amountOut > 0, 'AmountOut Zero');

        redeemReceipt.status = RedeemStatus.CANCELED;

        redeemInfo.USDseAmount -= redeemReceipt.USDseAmount;
        redeemInfo.pendingAmount -= redeemReceipt.amountOut;

        PENDING_REDEEM_AMOUNT -= redeemReceipt.amountOut;

        ISeERC20(USDse).safeTransfer(redeemReceipt.to, redeemReceipt.USDseAmount);
        emit CancelRedeem(_msgId, redeemReceipt.to, USDse, redeemReceipt.USDseAmount);
    }

    function _calculateMintOut(address _tokenOut, uint256 _amountIn, uint256 _fee) internal view returns (uint256) {
        uint256 amountOut = _amountIn;
        if (_fee > 0) {
            uint256 fee = (amountOut * _fee) / ZOOM;
            amountOut = amountOut - fee;
        }
        uint256 toTokenDecimals = _convertAmountToTokenDecimals(_tokenOut, amountOut);
        return toTokenDecimals;
    }

    function _calculateRedeemOut(address _tokenOut, uint256 _USDseAmount, uint256 _fee) internal view returns (uint256) {
        uint256 amountOut = _USDseAmount;
        if (_fee > 0) {
            uint256 fee = (amountOut * _fee) / ZOOM;
            amountOut = amountOut - fee;
        }
        uint256 to18Decimals = _convertAmountTo18Decimals(address(USDse), amountOut);
        uint256 toTokenDecimals = _convertAmountToTokenDecimals(_tokenOut, to18Decimals);
        return toTokenDecimals;
    }


    function _convertAmountTo18Decimals(address _token, uint256 _amount) internal view returns (uint256) {
        uint tokenDecimals = ISeERC20(_token).decimals();
        require(tokenDecimals <= 18, 'Minting: invalid token decimals');
        if (tokenDecimals >= 18) return _amount;
        return _amount * (10 ** (18 - tokenDecimals));
    }

    function _convertAmountToTokenDecimals(address _token, uint256 _amount) internal view returns (uint256) {
        uint tokenDecimals = ISeERC20(_token).decimals();
        require(tokenDecimals <= 18, 'Minting: invalid token decimals');
        if (tokenDecimals >= 18) return _amount;
        return _amount / (10 ** (18 - tokenDecimals));
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


