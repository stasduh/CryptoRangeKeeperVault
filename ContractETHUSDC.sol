// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin — pinned to a specific version so the contract compiles the
// same way every time, regardless of whatever OpenZeppelin ships after today.
import "@openzeppelin/contracts@5.6.1/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts@5.6.1/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts@5.6.1/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts@5.6.1/access/Ownable.sol";
import "@openzeppelin/contracts@5.6.1/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts@5.6.1/utils/cryptography/MessageHashUtils.sol";

// Uniswap's own tick/price math — NOT reimplemented by hand (this class of
// bit-shifting fixed-point math is exactly where hand-rolled code tends to
// introduce subtle, expensive bugs). Uniswap's original v3-core libraries
// are pinned to pragma <0.8.0 and won't compile here, so this uses the
// same math ported natively to 0.8.x as part of v4-core — same formulas,
// just a modern Solidity target. Confirmed via the official Uniswap GitHub
// before using: TickMath.sol here declares `pragma solidity ^0.8.0`, same
// for FullMath.sol and FixedPoint96.sol.
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {FixedPoint96} from "@uniswap/v4-core/src/libraries/FixedPoint96.sol";
// NOTE: v4-periphery's LiquidityAmounts.sol does NOT include
// getAmountsForLiquidity() (only the reverse direction — v4's architecture
// doesn't need it the way a v3-style NFT position does). That specific
// function is ported below in _getAmountsForLiquidity(), copied verbatim
// from Uniswap's audited v3-periphery LiquidityAmounts.sol (only the
// FullMath/FixedPoint96 source swapped for the 0.8.x-compatible ones above
// — the math itself is untouched):
// https://github.com/Uniswap/v3-periphery/blob/main/contracts/libraries/LiquidityAmounts.sol

/// @dev Minimal interface — only the functions this contract actually calls.
///      Deliberately not importing Uniswap's own v3-periphery package for
///      this part: it targets an older Solidity pragma (0.7.6) and pulling
///      in its full dependency tree risks compiler/version friction in
///      Remix for no real benefit here. This subset is stable and has been
///      unchanged for years.
interface INonfungiblePositionManager {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function mint(MintParams calldata params)
        external
        payable
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    struct DecreaseLiquidityParams {
        uint256 tokenId;
        uint128 liquidity;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    function decreaseLiquidity(DecreaseLiquidityParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    function collect(CollectParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

    function positions(uint256 tokenId)
        external
        view
        returns (
            uint96 nonce,
            address operator,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );
}

/// @dev Only the one read this contract needs from the pool itself.
interface IUniswapV3PoolMinimal {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
}

/// @title CryptoRangeKeeperVault
/// @notice Capital lifecycle: AML-gated deposit + share issuance (ERC-4626),
///         plus a keeper-only rebalance() that moves the vault's WETH/USDC
///         into a single Uniswap V3 position at whatever tick range the
///         off-chain keeper bot computes.
/// @dev Built on OpenZeppelin's audited ERC4626 rather than a custom
///      implementation — share-accounting bugs are one of the most common
///      ways vault contracts get drained, not worth reinventing.
///
///      totalAssets() is overridden to value idle USDC + idle WETH + the
///      open Uniswap V3 position (principal and uncollected fees), all
///      converted to USDC via the pool's current price. Without this, share
///      pricing would silently break the moment rebalance() moves funds out
///      of raw USDC — this was caught and fixed before any real deposits
///      happened against a rebalancing version of this contract.
///
///      NOT AUDITED. Deploy to testnet (Arbitrum Sepolia) first. Do not put
///      real user funds behind this without a professional security review.
contract CryptoRangeKeeperVault is ERC4626, Ownable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    /// @notice Address whose signature over (receiver, deadline, nonce) proves
    ///         the backend's AML check passed. Matches the private key held
    ///         server-side in Vercel (see api/aml-check.js / api/aml-sign.js)
    ///         — never the deployer's own key.
    address public amlSigner;

    /// @notice Per-address nonce, incremented on every successful deposit so
    ///         a signature can never be replayed to authorize a second deposit.
    mapping(address => uint256) public nonces;

    /// @notice Wallet that will receive Crypto Range Keeper's service commission.
    ///         Foundation only for now — no fee is actually taken anywhere yet.
    address public feeRecipient;

    /// @notice The only address allowed to call rebalance() — meant to be your
    ///         keeper bot's own wallet, separate from owner/amlSigner/feeRecipient
    ///         so a compromised bot key can only ever mess with position
    ///         placement, never touch admin functions or user deposits directly.
    address public keeper;

    /// @notice Uniswap V3 NonfungiblePositionManager (same address on most
    ///         EVM chains). Immutable — set once at deploy, never changes.
    INonfungiblePositionManager public immutable positionManager;

    /// @notice The specific Uniswap V3 pool this vault provides liquidity
    ///         into — passed in directly at deploy rather than derived from
    ///         the factory, so there's no ambiguity about which pool (this
    ///         project already found two same-fee-tier pools for the same
    ///         nominal pair that use different USDC variants).
    IUniswapV3PoolMinimal public immutable pool;

    /// @notice The vault's other working token (WETH on Arbitrum). The
    ///         ERC4626 `asset()` (USDC) is the other half of the pair.
    IERC20 public immutable pairToken;

    /// @notice Uniswap V3 fee tier for the pool this vault provides
    ///         liquidity into (500 = 0.05%).
    uint24 public immutable poolFee;

    /// @notice True if `asset()` (USDC) sorts as token0 in the pool
    ///         (Uniswap always orders the pair by address). Computed once at
    ///         deploy and reused everywhere, instead of re-sorting the two
    ///         addresses separately in rebalance() and totalAssets() — two
    ///         copies of the same comparison is exactly how these two
    ///         functions could quietly disagree with each other later.
    bool public immutable assetIsToken0;

    /// @notice tokenId of the vault's current open Uniswap V3 position.
    ///         0 means no open position yet.
    uint256 public currentPositionTokenId;

    /// @dev Internal one-shot gate: set true only for the duration of the
    ///      depositWithAmlCheck() call, so the inherited deposit()/mint()
    ///      can't be called directly without going through the AML check.
    bool private _amlGatePassed;

    uint256 private constant Q96 = 2 ** 96;

    event AmlSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event KeeperUpdated(address indexed oldKeeper, address indexed newKeeper);
    event AmlDeposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Rebalanced(
        uint256 indexed oldTokenId,
        uint256 indexed newTokenId,
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    );

    error AmlSignatureExpired();
    error AmlSignatureInvalid();
    error DirectDepositNotAllowed();
    error ZeroAddress();
    error DuplicateRoleAddress();
    error NotKeeper();

    modifier onlyKeeper() {
        if (msg.sender != keeper) revert NotKeeper();
        _;
    }

    /// @dev Sanity checks against fat-finger deploys — owner, amlSigner,
    ///      feeRecipient, and keeper must be four genuinely different,
    ///      non-zero wallets.
    constructor(
        IERC20 asset_,
        IERC20 pairToken_,
        uint24 poolFee_,
        address positionManager_,
        address pool_,
        address amlSigner_,
        address feeRecipient_,
        address keeper_,
        address initialOwner_
    )
        ERC4626(asset_)
        ERC20("Crypto Range Keeper Vault", "CRK")
        Ownable(initialOwner_)
    {
        if (
            amlSigner_ == address(0) ||
            feeRecipient_ == address(0) ||
            keeper_ == address(0) ||
            initialOwner_ == address(0) ||
            address(pairToken_) == address(0) ||
            positionManager_ == address(0) ||
            pool_ == address(0)
        ) {
            revert ZeroAddress();
        }
        if (
            amlSigner_ == feeRecipient_ ||
            amlSigner_ == initialOwner_ ||
            amlSigner_ == keeper_ ||
            feeRecipient_ == initialOwner_ ||
            feeRecipient_ == keeper_ ||
            initialOwner_ == keeper_
        ) {
            revert DuplicateRoleAddress();
        }

        amlSigner = amlSigner_;
        feeRecipient = feeRecipient_;
        keeper = keeper_;
        pairToken = pairToken_;
        poolFee = poolFee_;
        positionManager = INonfungiblePositionManager(positionManager_);
        pool = IUniswapV3PoolMinimal(pool_);
        assetIsToken0 = address(asset_) < address(pairToken_);
    }

    /// @notice Update the trusted AML signer address (e.g. if the backend's
    ///         signing key ever needs to rotate).
    function setAmlSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        if (newSigner == owner() || newSigner == feeRecipient || newSigner == keeper) revert DuplicateRoleAddress();
        emit AmlSignerUpdated(amlSigner, newSigner);
        amlSigner = newSigner;
    }

    /// @notice Update the wallet that collects Crypto Range Keeper's commission.
    function setFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert ZeroAddress();
        if (newRecipient == owner() || newRecipient == amlSigner || newRecipient == keeper) revert DuplicateRoleAddress();
        emit FeeRecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    /// @notice Update the keeper bot's wallet (e.g. rotating to a new server).
    function setKeeper(address newKeeper) external onlyOwner {
        if (newKeeper == address(0)) revert ZeroAddress();
        if (newKeeper == owner() || newKeeper == amlSigner || newKeeper == feeRecipient) revert DuplicateRoleAddress();
        emit KeeperUpdated(keeper, newKeeper);
        keeper = newKeeper;
    }

    /// @dev Same fat-finger protection as the constructor and the other
    ///      setters — the new owner can't already hold another role.
    function transferOwnership(address newOwner) public override onlyOwner {
        if (newOwner == amlSigner || newOwner == feeRecipient || newOwner == keeper) revert DuplicateRoleAddress();
        super.transferOwnership(newOwner);
    }

    /// @notice The only allowed entry point for deposits. Requires a fresh
    ///         signature from amlSigner authorizing `receiver` to deposit,
    ///         with an expiry (`deadline`) and a nonce baked in so the same
    ///         signature can't be replayed.
    function depositWithAmlCheck(
        uint256 assets,
        address receiver,
        uint256 deadline,
        bytes calldata signature
    ) external returns (uint256 shares) {
        if (block.timestamp > deadline) revert AmlSignatureExpired();

        uint256 nonce = nonces[receiver];
        bytes32 structHash = keccak256(
            abi.encodePacked(receiver, deadline, nonce, block.chainid, address(this))
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(structHash);

        if (ethSignedHash.recover(signature) != amlSigner) revert AmlSignatureInvalid();

        nonces[receiver] = nonce + 1; // burn this signature before external calls (checks-effects-interactions)

        _amlGatePassed = true;
        shares = deposit(assets, receiver);
        _amlGatePassed = false;

        emit AmlDeposit(msg.sender, receiver, assets, shares);
    }

    /// @dev Blocks the standard ERC4626 deposit() from being called directly —
    ///      only depositWithAmlCheck() may reach it.
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        if (!_amlGatePassed) revert DirectDepositNotAllowed();
        return super.deposit(assets, receiver);
    }

    /// @dev mint() is disabled entirely — depositWithAmlCheck() is asset-based.
    function mint(uint256, address) public pure override returns (uint256) {
        revert DirectDepositNotAllowed();
    }

    // withdraw() / redeem() are intentionally left as the standard, ungated
    // ERC4626 implementation — the AML check happens on the way IN, not on
    // withdrawal.

    /// @notice Moves the vault's liquidity to a new tick range. Called by the
    ///         keeper bot roughly once an hour. Deliberately does NOT
    ///         re-check timing, the 5%-distance-to-edge trigger, or sanity of
    ///         the tick values — all of that lives in the off-chain bot.
    /// @dev A compromised keeper key can burn/re-mint into a badly-chosen
    ///      range (temporarily inefficient), but decreaseLiquidity()/collect()
    ///      always return real tokens to this contract regardless of the new
    ///      range — there's no recipient parameter it controls pointing
    ///      outside this contract.
    function rebalance(int24 tickLower, int24 tickUpper) external onlyKeeper {
        uint256 oldTokenId = currentPositionTokenId;

        if (oldTokenId != 0) {
            (, , , , , , , uint128 liquidity, , , ,) = positionManager.positions(oldTokenId);

            if (liquidity > 0) {
                positionManager.decreaseLiquidity(
                    INonfungiblePositionManager.DecreaseLiquidityParams({
                        tokenId: oldTokenId,
                        liquidity: liquidity,
                        amount0Min: 0,
                        amount1Min: 0,
                        deadline: block.timestamp
                    })
                );
            }

            positionManager.collect(
                INonfungiblePositionManager.CollectParams({
                    tokenId: oldTokenId,
                    recipient: address(this),
                    amount0Max: type(uint128).max,
                    amount1Max: type(uint128).max
                })
            );
        }

        (address token0, address token1) = _sortedTokens();

        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        IERC20(token0).forceApprove(address(positionManager), balance0);
        IERC20(token1).forceApprove(address(positionManager), balance1);

        (uint256 newTokenId, , uint256 amount0, uint256 amount1) = positionManager.mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: poolFee,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0Desired: balance0,
                amount1Desired: balance1,
                amount0Min: 0,
                amount1Min: 0,
                recipient: address(this),
                deadline: block.timestamp
            })
        );

        // Revoke any leftover approval rather than leaving it standing.
        IERC20(token0).forceApprove(address(positionManager), 0);
        IERC20(token1).forceApprove(address(positionManager), 0);

        currentPositionTokenId = newTokenId;

        emit Rebalanced(oldTokenId, newTokenId, tickLower, tickUpper, amount0, amount1);
    }

    /// @notice Total vault value, expressed in `asset()` (USDC) — the number
    ///         ERC4626 uses to price shares on every deposit/withdraw.
    /// @dev Sums three things: idle USDC sitting on the contract, idle WETH
    ///      (converted via the pool's current price), and the open Uniswap
    ///      V3 position's principal + uncollected fees (also converted).
    ///      Uses the pool's spot price (slot0), not a TWAP — spot price is
    ///      manipulable within a single transaction/block on a low-liquidity
    ///      pool. This pool has $75M+ TVL (checked before choosing it), which
    ///      makes a same-block manipulation attack expensive, but it's a
    ///      known limitation worth revisiting if that liquidity ever drops
    ///      materially, or before scaling deposit sizes up significantly.
    function totalAssets() public view override returns (uint256) {
        uint256 idleUsdc = IERC20(asset()).balanceOf(address(this));
        uint256 idleWeth = pairToken.balanceOf(address(this));

        uint256 positionUsdc;
        uint256 positionWeth;

        uint256 tokenId = currentPositionTokenId;
        if (tokenId != 0) {
            (, , , , , int24 tickLower, int24 tickUpper, uint128 liquidity, , , uint128 tokensOwed0, uint128 tokensOwed1) =
                positionManager.positions(tokenId);

            if (liquidity > 0) {
                (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();

                (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(
                    sqrtPriceX96,
                    TickMath.getSqrtPriceAtTick(tickLower),
                    TickMath.getSqrtPriceAtTick(tickUpper),
                    liquidity
                );

                if (assetIsToken0) {
                    positionUsdc = amount0;
                    positionWeth = amount1;
                } else {
                    positionWeth = amount0;
                    positionUsdc = amount1;
                }
            }

            if (assetIsToken0) {
                positionUsdc += tokensOwed0;
                positionWeth += tokensOwed1;
            } else {
                positionWeth += tokensOwed0;
                positionUsdc += tokensOwed1;
            }
        }

        uint256 totalWeth = idleWeth + positionWeth;
        uint256 wethValueInUsdc = totalWeth == 0 ? 0 : _wethToUsdc(totalWeth);

        return idleUsdc + positionUsdc + wethValueInUsdc;
    }

    function _sortedTokens() private view returns (address token0, address token1) {
        return assetIsToken0
            ? (address(asset()), address(pairToken))
            : (address(pairToken), address(asset()));
    }

    /// @dev Converts a raw WETH amount into its USDC-equivalent at the
    ///      pool's current spot price.
    function _wethToUsdc(uint256 wethAmount) private view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();

        // priceX96 = (token1raw / token0raw) * 2^96, using raw token units —
        // this is the standard Uniswap V3 spot-price formula.
        uint256 priceX96 = FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), Q96);

        if (assetIsToken0) {
            // USDC is token0, WETH is token1 -> priceX96 converts token1(WETH) to token0(USDC)... 
            // actually priceX96 = token1/token0, so to go from WETH(token1) amount to USDC(token0):
            // usdc = weth / (token1/token0) = weth * token0/token1 = weth * Q96 / priceX96
            return FullMath.mulDiv(wethAmount, Q96, priceX96);
        } else {
            // WETH is token0, USDC is token1 -> priceX96 = token1(USDC)/token0(WETH) directly
            return FullMath.mulDiv(wethAmount, priceX96, Q96);
        }
    }

    // ---- Ported from Uniswap v3-periphery's LiquidityAmounts.sol ----
    // (audited, unchanged math; only FullMath/FixedPoint96 source swapped
    // for the 0.8.x-native versions from v4-core — see import comment above)

    function _getAmount0ForLiquidity(uint160 sqrtRatioAX96, uint160 sqrtRatioBX96, uint128 liquidity)
        private
        pure
        returns (uint256 amount0)
    {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        return FullMath.mulDiv(
            uint256(liquidity) << FixedPoint96.RESOLUTION,
            sqrtRatioBX96 - sqrtRatioAX96,
            sqrtRatioBX96
        ) / sqrtRatioAX96;
    }

    function _getAmount1ForLiquidity(uint160 sqrtRatioAX96, uint160 sqrtRatioBX96, uint128 liquidity)
        private
        pure
        returns (uint256 amount1)
    {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        return FullMath.mulDiv(liquidity, sqrtRatioBX96 - sqrtRatioAX96, FixedPoint96.Q96);
    }

    /// @dev Computes token0/token1 value for a given amount of liquidity at
    ///      the current pool price and a position's tick boundaries.
    function _getAmountsForLiquidity(
        uint160 sqrtRatioX96,
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) private pure returns (uint256 amount0, uint256 amount1) {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);

        if (sqrtRatioX96 <= sqrtRatioAX96) {
            amount0 = _getAmount0ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity);
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            amount0 = _getAmount0ForLiquidity(sqrtRatioX96, sqrtRatioBX96, liquidity);
            amount1 = _getAmount1ForLiquidity(sqrtRatioAX96, sqrtRatioX96, liquidity);
        } else {
            amount1 = _getAmount1ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity);
        }
    }
}