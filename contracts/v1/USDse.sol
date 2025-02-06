// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISeERC20} from "./interfaces/ISeERC20.sol";

contract USDse is ERC20, ERC20Burnable, ERC20Permit, ReentrancyGuard, Ownable {
    using SafeERC20 for ISeERC20;

    struct MintReceipt {
        address to;
        address tokenIn;
        uint256 amountIn;
        uint256 fee;
        uint256 amountOut;
    }

    modifier onlyAdmin {
        require(msg.sender == ADMIN);
        _;
    }

    mapping(uint256 msgId => MintReceipt receipt) public mintReceipts;
    mapping(address token => bool active) public tokens;
    mapping(address signer => bool active) public signers;
    address public TREASURY;
    address public ADMIN;
    uint256 constant public ZOOM = 10_000;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");


    event SetTreasury(
        address indexed treasury
    );

    event SetSigner(
        address indexed signer,
        bool indexed active
    );

    event SetToken(
        address indexed token,
        bool indexed active
    );

    event Mint(
        uint256 indexed msgId,
        address indexed to,
        address indexed tokenIn,
        uint256 amountIn,
        uint256 amountOut
    );

    constructor(address _admin, address _treasury, address _signer, address[] memory _initTokens) ERC20("USDse", "USDse") ERC20Permit("USDse") Ownable(msg.sender){
        require(_admin != address(0), '_admin Zero');
        require(_treasury != address(0), '_treasury Zero');
        require(_signer != address(0), '_signer Zero');
        require(_initTokens.length > 0, 'Empty _initTokens');

        for (uint256 i = 0; i < _initTokens.length; i++) {
            require(_initTokens[i] != address(0) && _initTokens[i].code.length > 0, 'Invalid Token Address');
            tokens[_initTokens[i]] = true;
        }

        TREASURY = _treasury;
        signers[_signer] = true;
        ADMIN = _admin;
    }

    function setTreasury(address _treasury) external onlyAdmin {
        require(_treasury != address(0), '_treasury Zero');
        TREASURY = _treasury;
        emit SetTreasury(_treasury);
    }

    function setSigner(address _signer, bool _active) external onlyAdmin {
        require(_signer != address(0), '_signer Zero');
        signers[_signer] = _active;
        emit SetSigner(_signer, _active);
    }

    function setToken(address _token, bool _active) external onlyAdmin {
        require(_token != address(0) && _token.code.length > 0, '_token Zero');
        tokens[_token] = _active;
        emit SetToken(_token, _active);
    }

    function mint(
        uint256 _msgId,
        address _tokenIn,
        uint256 _amountIn,
        uint256 _feeBps,
        uint256 _expire,
        bytes calldata _sig
    ) external nonReentrant {
        require(TREASURY != address(0), 'TREASURY Zero');
        require(mintReceipts[_msgId].to == address(0), 'Minted');
        require(block.timestamp <= _expire, 'Expired');
        require(tokens[_tokenIn], '_tokenIn Not Supported');
        require(_amountIn > 0, '_amountIn Zero');
        require(_feeBps >= 0 && _feeBps <= ZOOM, '_feeBps Invalid');

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        bytes32 data = keccak256(abi.encodePacked(
            _msgId,
            msg.sender,
            _tokenIn,
            _amountIn,
            _feeBps,
            _expire,
            chainId,
            address(this)));
        require(_verifySignature(data, _sig), 'Invalid Signature');

        uint256 amountOut = _calculateMintOut(_tokenIn, _amountIn, _feeBps);

        require(amountOut > 0, 'amountOut Zero');

        mintReceipts[_msgId] = MintReceipt(
            msg.sender,
            _tokenIn,
            _amountIn,
            _feeBps,
            amountOut
        );

        ISeERC20(_tokenIn).safeTransferFrom(msg.sender, TREASURY, _amountIn);
        _mint(msg.sender, amountOut);

        emit Mint(_msgId, msg.sender, _tokenIn, _amountIn, amountOut);
    }

    function _calculateMintOut(address tokenIn, uint256 _amountIn, uint256 _feeBps) internal view returns (uint256) {
        uint256 amountOut = _amountIn;
        if (_feeBps > 0) {
            uint256 fee = (amountOut * _feeBps) / ZOOM;
            amountOut = amountOut - fee;
        }
        uint256 to18Decimals = _convertAmountTo18Decimals(tokenIn, amountOut);
        uint256 toTokenDecimals = _convertAmountToTokenDecimals(address(this), to18Decimals);
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
