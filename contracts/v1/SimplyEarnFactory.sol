// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISeERC20} from "./interfaces/ISeERC20.sol";

contract SimplyEarnFactory is PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using SafeERC20 for ISeERC20;

    enum RedeemStatus {PENDING, DONE, CANCELED}

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
    mapping(uint256 msgId => RedeemReceipt receipt) public redeemReceipts;
    mapping(address user => RedeemInfo info) public redeemInfos;

    address public USDse;
    address public REDEEM_TOKEN;
    uint256 public LOCK_TIME;
    uint256 public PENDING_REDEEM_AMOUNT;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 constant public ZOOM = 10_000;
    uint256 constant public MAX_LOCK = 30 days;


    event SetUSDse(
        address indexed USDse
    );

    event SetRedeemToken(
        address indexed redeemToken
    );

    event SetSigner(
        address indexed signer,
        bool indexed active
    );

    event SetLockTime(
        uint256 indexed lockTime
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
        address _USDse,
        address _redeemToken
    ) external initializer {
        require(_admin != address(0), '_admin Zero Address');
        require(_signer != address(0), '_signer Zero Address');
        require(_USDse != address(0) && _USDse.code.length > 0, '_USDse Zero Address');
        require(_redeemToken != address(0) && _redeemToken.code.length > 0, '_redeemToken Zero Address');

        signers[_signer] = true;
        USDse = _USDse;
        REDEEM_TOKEN = _redeemToken;
        LOCK_TIME = 7 days;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, _admin);

        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
    }


    function setUSDse(address _USDse) external onlyRole(ADMIN_ROLE) {
        require(_USDse != address(0) && _USDse.code.length > 0, '_USDse Zero Address ');
        USDse = _USDse;
        emit SetUSDse(_USDse);
    }

    function setRedeemToken(address _redeemToken) external onlyRole(ADMIN_ROLE) {
        require(_redeemToken != address(0) && _redeemToken.code.length > 0, '_redeemToken Zero Address ');
        REDEEM_TOKEN = _redeemToken;
        emit SetRedeemToken(_redeemToken);
    }

    function setSigner(address _signer, bool _active) external onlyRole(ADMIN_ROLE) {
        require(_signer != address(0), '_signer Zero');
        signers[_signer] = _active;
        emit SetSigner(_signer, _active);
    }

    function setLockTime(uint256 _time) external onlyRole(ADMIN_ROLE) {
        require(_time >= 0 && _time <= MAX_LOCK, 'Max Lock');
        LOCK_TIME = _time;
        emit SetLockTime(LOCK_TIME);
    }

    function redeem(
        uint256 _msgId,
        uint256 _USDseAmount,
        uint256 _feeBps,
        uint256 _expire,
        bytes calldata _sig
    ) external nonReentrant {
        require(redeemReceipts[_msgId].to == address(0), 'Requested');
        require(_USDseAmount > 0, '_USDseAmount Zero');
        require(_feeBps >= 0 && _feeBps <= ZOOM, '_feeBps Invalid');
        require(block.timestamp <= _expire, 'Expired');
        require(USDse != address(0), 'USDse Zero');
        require(REDEEM_TOKEN != address(0), 'Redeem Token Zero');

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            msg.sender,
            _USDseAmount,
            _feeBps,
            _expire,
            chainId,
            address(this)));
        require(_verifySignature(data, _sig), 'Invalid Signature');

        uint256 amountOut = _calculateRedeemOut(REDEEM_TOKEN, _USDseAmount, _feeBps);
        require(amountOut > 0, 'amountOut Zero');

        redeemReceipts[_msgId] = RedeemReceipt(
            msg.sender,
            _USDseAmount,
            amountOut,
            _feeBps,
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
    ) external nonReentrant {
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
    ) external nonReentrant {
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
        require(tokenDecimals <= 18, 'Invalid Token Decimals');
        if (tokenDecimals >= 18) return _amount;
        return _amount * (10 ** (18 - tokenDecimals));
    }

    function _convertAmountToTokenDecimals(address _token, uint256 _amount) internal view returns (uint256) {
        uint tokenDecimals = ISeERC20(_token).decimals();
        require(tokenDecimals <= 18, 'Invalid Token Decimals');
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

}


