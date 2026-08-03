// SPDX-License-Identifier: MIT
pragma solidity 0.8.34; // security audit findings L002 (floating pragma) + L008 (outdated
                         // floor version) — was "^0.8.24", accepting any 0.8.x up to but not
                         // including 0.9.0. Pinned to the exact version we've actually been
                         // compiling and testing with throughout (Remix 0.8.34), so the
                         // contract can never silently compile with a DIFFERENT compiler
                         // version than the one it was verified against.

// OpenZeppelin — pinned to a specific version so the contract compiles the
// same way every time, regardless of whatever OpenZeppelin ships after today.
import "@openzeppelin/contracts@5.6.1/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts@5.6.1/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts@5.6.1/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts@5.6.1/access/Ownable2Step.sol";
import "@openzeppelin/contracts@5.6.1/utils/ReentrancyGuard.sol";
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

/// @dev Only the reads this contract needs from the pool itself.
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

    /// @notice Returns cumulative tick values at each offset in `secondsAgos`
    ///         — the raw data a TWAP is computed from. Requires the pool's
    ///         observation buffer to actually hold data going back that far;
    ///         see increaseObservationCardinalityNext() on the pool if it
    ///         doesn't (a one-time setup call, not something this contract
    ///         needs to do itself since Arbitrum's high-volume pools
    ///         typically already have a deep enough buffer).
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
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
///      Reviewed across multiple rounds of independent security audits
///      (see /audit on the site for the published report) — findings from
///      each round are addressed inline near the code they affect, tagged
///      "security audit finding" so the reasoning stays attached to the
///      code rather than living only in an external document.
///
///      DELIBERATE POLICY ON GAS OPTIMIZATION: this contract runs on
///      Arbitrum, where a full rebalance() costs on the order of $0.02-0.05
///      even fully unoptimized (observed directly, not estimated). A later
///      audit pass flagged ~20 categories of micro gas optimizations
///      (caching storage reads in memory, cheaper comparison operators,
///      struct-packing, and similar) — quantified before deciding: even a
///      generous combined estimate saves under $5/year at hourly rebalance
///      frequency. That's not worth the real cost of touching dozens of
///      places in an already-reviewed contract purely for gas — every such
///      edit is a fresh chance to introduce a bug the prior audit rounds
///      never had to consider. Deliberately skipped, not overlooked. Would
///      revisit this calculus on an L1 deployment or at a transaction
///      volume where the numbers actually changed the answer.
///
///      DEPLOYMENT SCOPE: this contract is intended for Arbitrum One only
///      — the whole gas-cost calculus above (sub-cent rebalances, immediate
///      close+reopen on every withdrawal, hourly keeper cycles) assumes
///      Arbitrum's very low gas prices specifically. None of that holds on
///      an L1 deployment (Ethereum mainnet), where the same operations
///      would cost orders of magnitude more — a straight redeploy without
///      revisiting these assumptions would be a mistake, not a port.
///      Likewise scoped to Uniswap V3 pools among the top ~10 pairs by
///      liquidity — the TWAP-manipulation resistance (see totalAssets()
///      below) and the slippage-tolerance defaults throughout this
///      contract were reasoned about and tested against a deep, liquid
///      pool (the real ETH/USDC 0.05% pool has $75M+ TVL); a shallow or
///      thinly-traded pair would need those assumptions re-examined, not
///      just a different pool address plugged in.
///
///      OPERATIONAL SECURITY: the four privileged addresses this contract
///      trusts (amlSigner, feeRecipient, keeper, owner) are held and
///      monitored by Crypto Range Keeper (cryptorangekeeper.com) — this
///      contract's own logic enforces role separation on-chain (no two of
///      the four may ever be the same address — see the constructor and
///      every setter below), but the actual custody and operational
///      security of each key (where it's stored, who can sign with it, key
///      rotation practices) is off-chain and outside what this contract or
///      its code comments can attest to.
///
///      PROJECT LINKS — for anyone reading this contract directly (e.g.
///      arriving here via a Revert Finance position listing, Arbiscan, or
///      any other on-chain explorer, not necessarily the site itself):
///        Website:  https://cryptorangekeeper.com/
///        Support:  support [at] cryptorangekeeper.com
///        GitHub:   https://github.com/stasduh/CryptoRangeKeeperVault
///        Discord:  https://discord.gg/smEFnSsX
///        X/Twitter: https://x.com/cryptorangekeep
///        Telegram: https://t.me/cryptorangekeeper
///        Audit report: https://cryptorangekeeper.com/audit
///
///      ROLE SEPARATION: this contract has four distinct privileged roles,
///      each with a narrow, specific purpose:
///        - owner: manages parameters and roles (setMinDeposit,
///          setWithdrawalCooldown, setPerformanceFeeBps, and appointing the
///          other three roles below). Two-step transfer (Ownable2Step) and
///          cannot renounce (see renounceOwnership() below).
///        - amlSigner: signs off-chain AML approvals required for deposits
///          (depositWithAmlCheck()) — can be rotated by the owner
///          (setAmlSigner()).
///        - keeper: the only address allowed to call rebalance() — can be
///          rotated by the owner (setKeeper()).
///        - feeRecipient: receives the service's performance fee cut —
///          can be rotated by the owner (setFeeRecipient()).
///      NONE of these four roles can move a depositor's funds anywhere
///      except back to that same depositor (or their designated receiver
///      on withdraw/redeem/withdrawMixed) — there is no function, on any
///      role, that transfers vault assets to an arbitrary address chosen
///      by owner/amlSigner/keeper/feeRecipient. The only address ever
///      credited from the vault's own token balances is feeRecipient, and
///      only with the specific, capped performanceFeeBps cut of realized
///      trading fees — never principal, never at an arbitrary amount.
///
///      NO PROXY PATTERN: this is a plain, non-upgradeable contract — no
///      delegatecall-based proxy, no initialize() function, no
///      post-deployment setup step of any kind. Every parameter is set
///      exactly once, inside the constructor, which by Solidity's own
///      construction can only ever run at deployment and can never be
///      called again afterward. There is no admin function anywhere in
///      this contract that changes the contract's own logic/bytecode —
///      the only way to "upgrade" this vault is a fresh deployment at a
///      new address, which is by design (see DEPLOYMENT SCOPE above for
///      why frequent redeployment is deliberately avoided).
///
///      ACCESS CONTROL: every administrative function is gated by the
///      correct modifier for its role (onlyOwner for owner-only functions,
///      onlyKeeper for rebalance()) — there is no administrative function
///      left ungated, and no function checks a role other than the one it
///      actually needs.
///
///      NO tx.origin: this contract never reads tx.origin anywhere, for
///      any purpose — every authorization check (onlyOwner, onlyKeeper,
///      AML signature recovery, allowance checks) uses msg.sender. Using
///      tx.origin for authorization is a well-known phishing vector (a
///      malicious contract can trick a user into a transaction that acts
///      "as" them via tx.origin, even though msg.sender would correctly
///      show the malicious contract as the immediate caller) — not a risk
///      this contract has any exposure to, since the pattern isn't used at
///      all, anywhere, not even for logging or informational purposes.
contract CryptoRangeKeeperVault is ERC4626, Ownable2Step, ReentrancyGuard {
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

    /// @notice "Cost basis" per address, in asset (USDC) terms — used to
    ///         compute each depositor's personal profit on the site without
    ///         ever scanning event history (expensive in RPC calls, was the
    ///         original design; this replaces it entirely).
    ///         personalProfit(user) = convertToAssets(balanceOf(user)) - costBasis[user]
    ///         Increased by the exact deposited amount on depositWithAmlCheck().
    ///         Decreased PROPORTIONALLY (not by the flat withdrawn amount —
    ///         that would misattribute principal vs. already-realized profit,
    ///         see _adjustCostBasisForWithdrawal()'s docstring) on withdraw()/
    ///         withdrawMixed(), and moved proportionally alongside CRK shares
    ///         on any plain transfer()/transferFrom() — otherwise a direct
    ///         share transfer would leave the recipient's shown profit
    ///         permanently wrong, since they never went through deposit().
    mapping(address => uint256) public costBasis;

    /// @notice Per-address withdrawal cooldown — prevents a griefing pattern
    ///         where a depositor with a trivial amount (e.g. $10 in a $1M
    ///         vault) repeatedly triggers withdraw()/withdrawMixed() in a
    ///         tight loop (e.g. every minute) to force repeated position
    ///         close+reopen cycles. Each cycle now reopens immediately (no
    ///         more idle-time griefing — see _reopenPositionAfterWithdrawal()),
    ///         but STILL incurs real slippage against the ENTIRE vault's
    ///         liquidity each time, bounded by WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS
    ///         but nonzero — a cost paid by every depositor's share of
    ///         totalAssets(), not just the griefer's own tiny withdrawal.
    ///         Attack cost to the griefer is just their own gas; harm is
    ///         socialized across the whole pool. One withdrawal per address
    ///         per cooldown period closes this off — applies uniformly to
    ///         BOTH withdraw()/redeem() (via _withdraw()) and
    ///         withdrawMixed(), keyed on the SHARE OWNER (not msg.sender, so
    ///         an allowance-based caller can't bypass it by rotating
    ///         callers), sharing one timestamp so alternating between the
    ///         two functions doesn't bypass it either.
    mapping(address => uint256) public lastWithdrawalAt;

    /// @notice Hard ceiling on withdrawalCooldown below — even the owner
    ///         can never set the real cooldown ABOVE 1 hour, only at or
    ///         below it. Caps how much a compromised or careless owner key
    ///         could inconvenience legitimate withdrawals by raising the
    ///         wait time; owner can still shorten it freely (e.g. to 30
    ///         minutes) if the griefing risk is judged low enough not to
    ///         need the full hour, but can never lengthen it past this.
    uint256 public constant MAX_WITHDRAWAL_COOLDOWN = 1 hours;

    /// @notice The actual enforced cooldown — starts at the maximum
    ///         (MAX_WITHDRAWAL_COOLDOWN) and is owner-adjustable downward
    ///         only via setWithdrawalCooldown() below.
    uint256 public withdrawalCooldown = 1 hours;

    /// @notice Minimum deposit amount, in asset() (USDC) raw units. Owner-
    ///         adjustable, no upper cap (deliberate — owner is trusted,
    ///         matches how performanceFeeBps/keeper/amlSigner are all
    ///         already owner-controlled without needing a second key to
    ///         co-sign every parameter change).
    ///         Raises the cost of a Sybil-style griefing pattern: spread a
    ///         withdrawal-cooldown bypass across many wallets, each holding
    ///         just enough to withdraw once an hour with a real deposit
    ///         behind it. A higher minimum means more capital has to be
    ///         genuinely locked up per additional wallet in the attack —
    ///         see lastWithdrawalAt's docstring for the full scenario this
    ///         complements. Starts low (deliberately, at the project's
    ///         current small scale) and is meant to be raised by the owner
    ///         as real TVL grows and the attack economics start to matter
    ///         more.
    uint256 public minDeposit = 1e6; // $1, at USDC's 6 decimals

    /// @notice Personal income from providing liquidity (trading fees),
    ///         INDEPENDENT of ETH price movement — unlike personalProfit()/
    ///         costBasis above (which reflect the full financial result,
    ///         including mark-to-market revaluation of the WETH portion).
    ///         This answers a different question: "how much did my money
    ///         actually earn in fees", not "how much did my position's
    ///         value go up or down".
    ///
    ///         Standard reward-accrual pattern (same as MasterChef and most
    ///         staking contracts): one vault-wide, ever-growing "yield per
    ///         share" index (moves only when yield is realized, in
    ///         _closeOldPosition()), and each user has their own "checkpoint"
    ///         in that index (yieldDebt), updated on every change to their
    ///         share balance. The difference between the current index and
    ///         a user's checkpoint, multiplied by their balance, is their
    ///         not-yet-settled ("pending") yield; personalYieldEarnedUsdc/Weth
    ///         is the already-settled portion (only ever grows — withdrawing
    ///         part of the balance never reduces it).
    ///
    ///         IMPORTANT (security audit finding #2, round 3): this grows
    ///         on the NET yield, AFTER the service's fee cut — not the same
    ///         gross figure as totalYieldEarnedUsdc/Weth (that figure stays
    ///         gross deliberately, for public-facing statistics). Otherwise
    ///         personalFeesEarnedUsdValue() would show the user money that
    ///         has already physically left to feeRecipient and isn't in
    ///         totalAssets() anymore — misleading them.
    uint256 private constant YIELD_PRECISION = 1e18;

    uint256 public accYieldPerShareUsdc;
    uint256 public accYieldPerShareWeth;

    mapping(address => uint256) private _yieldDebtUsdc;
    mapping(address => uint256) private _yieldDebtWeth;

    mapping(address => uint256) public personalYieldEarnedUsdc;
    mapping(address => uint256) public personalYieldEarnedWeth;

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

    /// @notice Cumulative performance fees ever sent to feeRecipient, tracked
    ///         separately per token since fees are paid in whichever token
    ///         they were earned in (WETH, USDC, or a mix), never converted.
    ///         Kept on-chain specifically so this number isn't something
    ///         only the backend claims — anyone can read it directly.
    ///         NOTE: this is the SERVICE'S cut (performanceFeeBps), not the
    ///         depositors' total yield — see totalYieldEarnedUsdc/Weth below
    ///         for the number meant to be shown to users on the site.
    uint256 public totalFeesCollectedUsdc;
    uint256 public totalFeesCollectedWeth;

    /// @notice Cumulative GROSS yield ever earned from providing liquidity
    ///         (100% of accrued trading fees, before the service's cut is
    ///         taken out) — this is what depositors collectively earned,
    ///         and the number meant to be shown publicly on the site as
    ///         "fees earned". Tracked the same way as totalFeesCollected*
    ///         above (read from tokensOwed0/1 before any liquidity is
    ///         touched), just without the performanceFeeBps cut applied.
    uint256 public totalYieldEarnedUsdc;
    uint256 public totalYieldEarnedWeth;

    /// @dev Internal one-shot gate: set true only for the duration of the
    ///      depositWithAmlCheck() call, so the inherited deposit()/mint()
    ///      can't be called directly without going through the AML check.
    bool private _amlGatePassed;

    uint256 private constant Q96 = 2 ** 96;

    /// @notice Cut of *earned trading fees* (not principal, not deposits,
    ///         not withdrawals) sent to feeRecipient — in basis points
    ///         (500 = 5%). Computed from the Uniswap position's
    ///         tokensOwed0/tokensOwed1, read BEFORE any liquidity is removed
    ///         on a given close — that field only ever holds accrued trading
    ///         fees at that point (see _closeOldPosition for why).
    uint256 public performanceFeeBps = 500;

    /// @notice Sanity ceiling on performanceFeeBps — even the owner can't set
    ///         it above this, so a compromised or careless owner key can't
    ///         redirect most/all of the yield.
    uint256 public constant MAX_PERFORMANCE_FEE_BPS = 2000; // 20%

    // ---- TWAP (security audit findings #1 and #3) ----
    // Two SEPARATE windows for two different jobs — using one window for
    // both was considered and rejected: totalAssets() wants a long, hard-
    // to-manipulate window since it's a value-of-record used to price every
    // deposit/withdrawal, while the rebalance() range check wants a much
    // shorter window so it doesn't spuriously reject a bot that reads live
    // slot0() and rebalances hourly — a 20-minute-lagging reference would
    // routinely disagree with an honest, fast-moving market.
    uint32 public constant TOTAL_ASSETS_TWAP_WINDOW = 1200; // 20 minutes — share pricing
    uint32 public constant RANGE_CHECK_TWAP_WINDOW = 300;   // 5 minutes — rebalance() sanity check

    /// @notice Max allowed distance (in ticks) between either edge of a
    ///         keeper-proposed range and the 5-minute TWAP tick — roughly
    ///         ±10% in price terms (ln(1.10)/ln(1.0001) ≈ 953.15, rounded).
    ///         Exists specifically to bound the damage from a compromised
    ///         keeper key (see security audit finding #3): even with the
    ///         private key, an attacker can't push the range out to
    ///         something like [-887272, 887272] (all-price-range = zero
    ///         concentration = "Denial of Yield") — every real range this
    ///         vault ever sets is within a few % of price by design
    ///         (BUFFER_FAR_PCT tops out at 3% in the bot's own config), so
    ///         10% leaves generous headroom for honest operation while still
    ///         catching the actual attack this exists to stop.
    int24 public constant RANGE_CHECK_TOLERANCE_TICKS = 953;

    event AmlSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event KeeperUpdated(address indexed oldKeeper, address indexed newKeeper);
    event PerformanceFeeUpdated(uint256 oldBps, uint256 newBps);
    event MinDepositUpdated(uint256 oldMinDeposit, uint256 newMinDeposit);
    event WithdrawalCooldownUpdated(uint256 oldCooldown, uint256 newCooldown);
    event PerformanceFeeCollected(uint256 feeToken0, uint256 feeToken1);
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
    error FeeTooHigh();
    error RangeTooFarFromTwap();
    error InsufficientPoolValue();
    error InsufficientIdleAssetsForWithdrawal();
    error WithdrawalCooldownActive(uint256 availableAt);
    error DepositBelowMinimum(uint256 minimum);
    error WithdrawalCooldownTooHigh();
    error RenounceOwnershipDisabled();
    error LiquidityOverflow();
    error TickOverflow();

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
        // Security audit finding L006: asset_ (USDC) was missing from this
        // list — ERC4626's own constructor doesn't reliably catch a zero
        // address here either (its _tryGetAssetDecimals() uses a low-level
        // staticcall that just returns success=false on a no-code address,
        // silently defaulting to 18 decimals rather than reverting).
        if (
            address(asset_) == address(0) ||
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

    /// @notice Update the performance fee taken from earned trading fees.
    ///         Capped at MAX_PERFORMANCE_FEE_BPS regardless of who calls this.
    function setPerformanceFeeBps(uint256 newBps) external onlyOwner {
        if (newBps > MAX_PERFORMANCE_FEE_BPS) revert FeeTooHigh();
        emit PerformanceFeeUpdated(performanceFeeBps, newBps);
        performanceFeeBps = newBps;
    }

    /// @notice Update the minimum deposit amount (see minDeposit's own
    ///         docstring for why this exists). Deliberately uncapped —
    ///         owner is already trusted with performanceFeeBps, keeper, and
    ///         amlSigner without a second key required, this is no
    ///         different in kind.
    function setMinDeposit(uint256 newMinDeposit) external onlyOwner {
        emit MinDepositUpdated(minDeposit, newMinDeposit);
        minDeposit = newMinDeposit;
    }

    /// @notice Shorten the withdrawal cooldown (see lastWithdrawalAt's own
    ///         docstring for why it exists) — e.g. down to 30 minutes, if
    ///         the griefing risk at the current TVL is judged low enough
    ///         not to need the full hour. Can only ever be set AT OR BELOW
    ///         MAX_WITHDRAWAL_COOLDOWN (1 hour) — never above it, even by
    ///         the owner; see that constant's own docstring for why.
    function setWithdrawalCooldown(uint256 newCooldown) external onlyOwner {
        if (newCooldown > MAX_WITHDRAWAL_COOLDOWN) revert WithdrawalCooldownTooHigh();
        emit WithdrawalCooldownUpdated(withdrawalCooldown, newCooldown);
        withdrawalCooldown = newCooldown;
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
    ///      Security audit finding L009: now two-step (Ownable2Step) —
    ///      this call only proposes `newOwner`; they must separately call
    ///      acceptOwnership() themselves to actually take over. Protects
    ///      against transferring ownership to a mistyped or unreachable
    ///      address, which under plain Ownable would be immediate and
    ///      irreversible — for a contract with no way to recover a lost
    ///      owner role (no admin backdoor, by design), that mistake would
    ///      be permanent.
    function transferOwnership(address newOwner) public override onlyOwner {
        if (newOwner == amlSigner || newOwner == feeRecipient || newOwner == keeper) revert DuplicateRoleAddress();
        super.transferOwnership(newOwner);
    }

    /// @notice Disabled — this vault always needs an active owner to manage
    ///         amlSigner/keeper/feeRecipient roles; renouncing would
    ///         permanently orphan those functions with no recovery path
    ///         (no admin backdoor exists, by design). Related to security
    ///         audit finding L009 — Ownable2Step protects transferOwnership()
    ///         from typos, but doesn't guard renounceOwnership() the same
    ///         way, so it's blocked outright instead.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
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
    ) external nonReentrant returns (uint256 shares) {
        if (assets < minDeposit) revert DepositBelowMinimum(minDeposit);
        if (block.timestamp > deadline) revert AmlSignatureExpired();

        uint256 nonce = nonces[receiver];
        bytes32 structHash = keccak256(
            abi.encodePacked(receiver, deadline, nonce, block.chainid, address(this))
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(structHash);

        if (ethSignedHash.recover(signature) != amlSigner) revert AmlSignatureInvalid();

        nonces[receiver] = nonce + 1; // burn this signature before external calls (checks-effects-interactions)

        _settleYieldBefore(receiver);

        _amlGatePassed = true;
        shares = deposit(assets, receiver);
        _amlGatePassed = false;

        _resetYieldDebtAfter(receiver);
        costBasis[receiver] += assets;

        emit AmlDeposit(msg.sender, receiver, assets, shares);
    }

    /// @dev Blocks the standard ERC4626 deposit() from being called directly —
    ///      only depositWithAmlCheck() may reach it.
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        if (!_amlGatePassed) revert DirectDepositNotAllowed();
        return super.deposit(assets, receiver);
    }

    /// @dev mint() is disabled entirely — depositWithAmlCheck() is asset-based.
    ///      Security audit finding #4c: this technically breaks strict
    ///      ERC-4626 compliance (external integrators expecting a working
    ///      mint() will find it always reverts). Deliberate tradeoff, not an
    ///      oversight: every deposit path has to go through the AML check in
    ///      depositWithAmlCheck(), and that function is asset-denominated
    ///      (matches what the off-chain AML signature actually authorizes).
    ///      A working share-denominated mint() would need its own separate
    ///      AML-gated wrapper anyway — not worth the added surface area for
    ///      a path nothing currently needs. Compliance took priority over
    ///      full standard conformance here.
    function mint(uint256, address) public pure override returns (uint256) {
        revert DirectDepositNotAllowed();
    }

    /// @dev Overridden purely for costBasis bookkeeping (see its own
    ///      docstring above) — the actual transfer logic doesn't change,
    ///      it's fully delegated to super.transfer()/transferFrom() as
    ///      before. Computed BEFORE the transfer itself, while
    ///      balanceOf(from) still reflects the pre-transfer balance.
    function transfer(address to, uint256 value) public override(ERC20, IERC20) returns (bool) {
        _adjustCostBasisForTransfer(msg.sender, to, value);
        _settleYieldBefore(msg.sender);
        _settleYieldBefore(to);
        bool ok = super.transfer(to, value);
        _resetYieldDebtAfter(msg.sender);
        _resetYieldDebtAfter(to);
        return ok;
    }

    function transferFrom(address from, address to, uint256 value) public override(ERC20, IERC20) returns (bool) {
        _adjustCostBasisForTransfer(from, to, value);
        _settleYieldBefore(from);
        _settleYieldBefore(to);
        bool ok = super.transferFrom(from, to, value);
        _resetYieldDebtAfter(from);
        _resetYieldDebtAfter(to);
        return ok;
    }

    // withdraw() / redeem() are intentionally left ungated (unlike deposit) —
    // the AML check happens on the way IN, not on withdrawal. Both funnel
    // through ERC4626's internal _withdraw() hook below, which is where the
    // "pull from the open position if idle balance is short" logic lives —
    // so both functions get it automatically, no separate override needed
    // for each.

    /// @dev Standard ERC4626 withdrawal just transfers `assets` straight out
    ///      of the contract's own balance — which fails once funds are
    ///      parked in an open Uniswap position instead of sitting idle as
    ///      plain USDC (confirmed by testing: reverts with "ERC20: transfer
    ///      amount exceeds balance"). If idle balance is short, this closes
    ///      the ENTIRE current position first (not just the needed slice —
    ///      partial withdrawal would need proportional-liquidity math, more
    ///      moving parts to get wrong) so the transfer below has enough to
    ///      work with. The keeper's next scheduled rebalance() reopens a
    ///      position from whatever's left.
    ///
    ///      Security audit finding #4b: the fee-to-feeRecipient transfer
    ///      inside _closeOldPosition() above happens before super._withdraw()
    ///      finishes — strictly not textbook checks-effects-interactions
    ///      order. Considered reordering, but the position genuinely has to
    ///      be closed FIRST to produce the USDC this function transfers out,
    ///      so the fee-transfer can't be moved after without restructuring
    ///      much more of the flow for no real safety gain: this function is
    ///      already nonReentrant, and both possible recipients here are
    ///      plain USDC/WETH — neither has a transfer callback a reentrant
    ///      call could hook into. Documented rather than force-reordered.
    /// @dev Security audit finding: griefing via repeated tiny withdrawals
    ///      in a tight loop, forcing repeated position close+reopen cycles
    ///      that each incur real slippage against the WHOLE vault's
    ///      liquidity, not just the griefer's own tiny amount — see
    ///      lastWithdrawalAt's own docstring for the full attack scenario.
    ///      Called first thing in both _withdraw() and withdrawMixed(),
    ///      keyed on the share owner so it can't be bypassed by rotating
    ///      which address calls in (allowance-based withdrawals still key
    ///      on whose shares are actually being drawn down).
    function _enforceWithdrawalCooldown(address owner_) private {
        uint256 availableAt = lastWithdrawalAt[owner_] + withdrawalCooldown;
        if (block.timestamp < availableAt) revert WithdrawalCooldownActive(availableAt);
        lastWithdrawalAt[owner_] = block.timestamp;
    }

    /// @dev Proportionally reduces costBasis[owner_] on withdrawal — NOT by
    ///      the flat withdrawn amount (assets), which would be wrong: if,
    ///      say, half the position's current value was withdrawn, the
    ///      "cost basis" should shrink by half too, not by the dollar
    ///      amount withdrawn — otherwise the yield shown on the remaining
    ///      share would be overstated (flat subtraction implicitly treats
    ///      the whole withdrawal as a "clean return of principal", when in
    ///      reality it's a proportional mix of principal and already-
    ///      realized profit).
    ///      Single entry point — reads balanceOf(owner_) BEFORE _burn() is
    ///      called anywhere further down the stack — called as the first
    ///      line in both _withdraw() and withdrawMixed(), before the burn
    ///      itself.
    function _adjustCostBasisForWithdrawal(address owner_, uint256 shares) private {
        uint256 balanceBefore = balanceOf(owner_);
        if (balanceBefore == 0) return;
        // Security audit finding M001: the integer division here
        // (multiplication already happens BEFORE the division — the
        // correct order, which avoids the worse version of this issue)
        // loses at most 1 raw unit per call — at most $0.000001 even with
        // costBasis up to $1,000,000. Deliberately not adding a scaling
        // factor (like YIELD_PRECISION next to accYieldPerShare) — the
        // effect is practically indistinguishable from zero, not worth the
        // added complexity.
        uint256 reduction = (costBasis[owner_] * shares) / balanceBefore;
        costBasis[owner_] -= reduction;
    }

    /// @dev Same proportional logic, but for a plain transfer()/
    ///      transferFrom() between wallets — without this, costBasis would
    ///      stay stuck on the original address, and personalProfit() for
    ///      the recipient of the shares would be wrong (they'd have the
    ///      shares, but no corresponding contribution recorded in the
    ///      counter), even though they never deposited directly.
    function _adjustCostBasisForTransfer(address from, address to, uint256 value) private {
        uint256 balanceBefore = balanceOf(from);
        if (balanceBefore == 0) return;
        // Security audit finding M001 — same case as
        // _adjustCostBasisForWithdrawal() above: at most $0.000001 lost per
        // call, deliberately left unscaled, see the comment there.
        uint256 transferredBasis = (costBasis[from] * value) / balanceBefore;
        costBasis[from] -= transferredBasis;
        costBasis[to] += transferredBasis;
    }

    /// @dev Call BEFORE any change to a user's share balance — "settles"
    ///      their not-yet-accounted-for (pending) yield against their
    ///      CURRENT (pre-change) balance into personalYieldEarnedUsdc/Weth,
    ///      which only ever grow and won't be affected by the balance
    ///      change that follows. Doesn't touch the share balance itself and
    ///      makes no external calls — only reads/writes this contract's own
    ///      mappings.
    function _settleYieldBefore(address user) private {
        uint256 bal = balanceOf(user);
        if (bal == 0) return;
        uint256 pendingUsdc = (bal * accYieldPerShareUsdc) / YIELD_PRECISION - _yieldDebtUsdc[user];
        uint256 pendingWeth = (bal * accYieldPerShareWeth) / YIELD_PRECISION - _yieldDebtWeth[user];
        personalYieldEarnedUsdc[user] += pendingUsdc;
        personalYieldEarnedWeth[user] += pendingWeth;
    }

    /// @dev Call AFTER any change to a user's share balance — recomputes
    ///      their "checkpoint" against the already-updated NEW balance, so
    ///      future yield isn't double-counted or lost on the next settle.
    function _resetYieldDebtAfter(address user) private {
        uint256 bal = balanceOf(user);
        _yieldDebtUsdc[user] = (bal * accYieldPerShareUsdc) / YIELD_PRECISION;
        _yieldDebtWeth[user] = (bal * accYieldPerShareWeth) / YIELD_PRECISION;
    }

    /// @dev Standard ERC4626 withdrawal just transfers `assets` straight out
    ///      of the contract's own balance — which fails once funds are
    ///      parked in an open Uniswap position instead of sitting idle as
    ///      plain USDC. If idle balance is short, closes the position first
    ///      so the transfer below has something to work with.
    ///
    ///      Security audit finding #1 fix (3rd round): closing the position
    ///      doesn't guarantee ENOUGH idle USDC ends up on the contract — if
    ///      the position was mostly WETH at close time (e.g. ETH price ran
    ///      up), idle USDC after closing can still fall short of `assets`,
    ///      and the plain ERC20 transfer inside super._withdraw() below
    ///      would revert with an unhelpful "transfer amount exceeds
    ///      balance" — permanently blocking this user's plain withdraw()
    ///      until market conditions happened to flip the composition back.
    ///      Now checked explicitly, with a clear error pointing at the real
    ///      fix: use withdrawMixed() instead, which pays the WETH shortfall
    ///      directly rather than requiring pure USDC.
    ///
    ///      Security audit finding #3 fix: closing the ENTIRE position for
    ///      a withdrawal — even a small one relative to the vault's total
    ///      size — otherwise left the REMAINING capital idle (earning
    ///      nothing) until the keeper's next scheduled rebalance(), up to
    ///      an hour away. Cheap to repeat (Arbitrum gas is negligible) and
    ///      harms every other depositor's yield, not just the withdrawer's
    ///      own. Fixed by reopening a position immediately, in the SAME
    ///      transaction, using whatever capital remains after paying out —
    ///      see _reopenPositionAfterWithdrawal()'s own docstring for why
    ///      this was chosen over true proportional partial withdrawal.
    function _withdraw(
        address caller,
        address receiver,
        address owner_,
        uint256 assets,
        uint256 shares
    ) internal override nonReentrant {
        _enforceWithdrawalCooldown(owner_);
        _adjustCostBasisForWithdrawal(owner_, shares);
        _settleYieldBefore(owner_);

        bool closedPosition = false;
        int24 closedTickLower;
        int24 closedTickUpper;

        // Static-analysis note (Slither): this first read is NOT the
        // security-critical one — it only decides whether to enter the
        // closing branch below at all. The value that actually gates the
        // payout is re-read fresh immediately after the external close
        // call (see the second assignment to idleBalance a few lines down,
        // right before the real check) — that's the read that matters, and
        // it's already always current. Even if this first read were somehow
        // stale, the worst case is an incorrect decision on whether to
        // close (over- or under-eager), never an incorrect payout — and
        // this whole function is nonReentrant, so no other call can
        // interleave and make it stale in the first place.
        uint256 idleBalance = IERC20(asset()).balanceOf(address(this));
        if (idleBalance < assets && currentPositionTokenId != 0) {
            (closedTickLower, closedTickUpper, closedPosition) = _closeCurrentPositionWithOnChainSlippageProtection();
            idleBalance = IERC20(asset()).balanceOf(address(this));
            if (idleBalance < assets) revert InsufficientIdleAssetsForWithdrawal();
        }

        super._withdraw(caller, receiver, owner_, assets, shares);

        if (closedPosition) {
            _reopenPositionAfterWithdrawal(closedTickLower, closedTickUpper);
        }

        _resetYieldDebtAfter(owner_);
    }

    /// @notice Basis-point tolerance used for the on-chain-computed slippage
    ///         minimum on withdrawal-triggered position closes (1% = 100).
    ///         Deliberately generous compared to what a bot could achieve
    ///         with a fresh off-chain quote — this path has no bot feeding
    ///         it real-time numbers, just a spot-price snapshot in the same
    ///         transaction, so the tolerance only needs to cover this one
    ///         transaction's own execution, not a longer lag.
    uint256 public constant WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS = 100;

    /// @dev Closes the currently open position with a modest, self-computed
    ///      slippage minimum (security audit finding #2's fix extended to
    ///      the withdrawal path too, not just rebalance() — decreaseLiquidity()
    ///      is exactly as sandwichable here as it is there). Shared by both
    ///      the standard withdraw()/redeem() path above and withdrawMixed()
    ///      below.
    ///
    ///      Real-world bug caught in production: this originally computed
    ///      "expected" amounts via _liquidityValue(), which uses the
    ///      20-minute TWAP (correct for totalAssets()'s share pricing, which
    ///      is what that function exists for). But decreaseLiquidity() below
    ///      executes at SPOT price in the same block — if spot had drifted
    ///      more than the 1% tolerance away from the 20-minute-old TWAP
    ///      (ordinary market movement, not manipulation), the TWAP-based
    ///      "expected" minimum came out higher than what decreaseLiquidity()
    ///      could actually deliver, and Uniswap's own internal check
    ///      reverted with "Price slippage check" on every withdrawal. Fixed
    ///      by using spot price as the reference here instead — appropriate
    ///      specifically because this minimum only protects THIS transaction's
    ///      own execution against being sandwiched, not share pricing against
    ///      manipulation (that protection lives in totalAssets()'s TWAP,
    ///      untouched by this fix).
    ///
    ///      Returns the closed position's tick bounds (security audit
    ///      finding #3 fix — see _reopenPositionAfterWithdrawal()'s
    ///      docstring for why the caller needs these) and whether there was
    ///      actually a position to close in the first place.
    function _closeCurrentPositionWithOnChainSlippageProtection()
        private
        returns (int24 closedTickLower, int24 closedTickUpper, bool hadPosition)
    {
        uint256 tokenId = currentPositionTokenId;
        (, , , , , int24 tickLower, int24 tickUpper, uint128 liquidity, , , , ) =
            positionManager.positions(tokenId);

        uint256 amount0Min;
        uint256 amount1Min;
        if (liquidity > 0) {
            (uint160 sqrtPriceX96Spot, , , , , , ) = pool.slot0();
            (uint256 expected0, uint256 expected1) = _getAmountsForLiquidity(
                sqrtPriceX96Spot,
                TickMath.getSqrtPriceAtTick(tickLower),
                TickMath.getSqrtPriceAtTick(tickUpper),
                liquidity
            );
            amount0Min = (expected0 * (10000 - WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS)) / 10000;
            amount1Min = (expected1 * (10000 - WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS)) / 10000;
        }

        _closeOldPosition(tokenId, amount0Min, amount1Min, block.timestamp);
        currentPositionTokenId = 0;

        return (tickLower, tickUpper, true);
    }

    /// @dev Security audit finding #3 fix — a compromised-free but still
    ///      real griefing vector: ANY depositor could force-close the
    ///      entire vault position via a withdrawal that exceeds idle USDC,
    ///      leaving the REST of the vault's capital idle (earning nothing)
    ///      until the keeper's next scheduled rebalance() — up to an hour,
    ///      and repeatable by the same actor indefinitely at near-zero cost
    ///      (Arbitrum gas). True proportional partial-withdrawal (only
    ///      remove the liquidity actually needed) was considered and
    ///      rejected as the fix — meaningfully more complex math for a
    ///      problem this solves more simply: reopen a position immediately,
    ///      in the SAME transaction, using whatever capital remains after
    ///      the withdrawal — gas cost for the reopen falls on the
    ///      withdrawing user, who was already paying gas for this
    ///      transaction regardless.
    ///
    ///      Reuses the just-closed position's OWN tick bounds rather than
    ///      computing a new range — deliberate: this function has no bot
    ///      feeding it a freshly-calculated strategic range, and the old
    ///      range is a reasonable default until the keeper's next cycle
    ///      naturally re-optimizes it (may end up less than optimal if the
    ///      withdrawal itself shifted the vault's remaining composition —
    ///      acceptable tradeoff, corrected on the next real rebalance()).
    ///      Slippage protection computed the same way as the close above —
    ///      spot price, same transaction, exact on-chain integer math (not
    ///      the bot's off-chain floating-point approximation, so none of
    ///      that precision-mismatch class of bug applies here).
    ///
    ///      IMPORTANT: does NOT reuse _openNewPosition() even though the
    ///      logic is nearly identical — Solidity's try/catch only wraps
    ///      external calls, not calls to private functions, so mint() is
    ///      called directly here inside its own try/catch. This is
    ///      deliberate defense-in-depth: if the mint reverts for any
    ///      unforeseen reason, this function must fail SILENTLY (skip
    ///      reopening, leave funds idle for the next real rebalance) rather
    ///      than reverting — otherwise a failure in this best-effort
    ///      optimization would block the withdrawal itself, defeating the
    ///      entire point of this fix. Small deliberate duplication of
    ///      _openNewPosition()'s approve+mint logic rather than touching
    ///      that already-audited function to add a try/catch branch it
    ///      doesn't otherwise need (rebalance() SHOULD revert on a real
    ///      mint failure — that's a keeper problem to see and fix, not
    ///      something to silently swallow).
    /// @notice Emitted whenever _reopenPositionAfterWithdrawal() didn't end
    ///         up minting a new position — the real reason a withdrawal's
    ///         leftover capital sat idle instead of reopening immediately.
    ///         Never reverts anything on its own (this is purely
    ///         informational — see _reopenPositionAfterWithdrawal()'s own
    ///         docstring for why a failed reopen must never block the
    ///         withdrawal itself), but without this event there was
    ///         previously no way to tell WHY a reopen didn't happen short
    ///         of manually reconstructing it from raw token transfer logs.
    event ReopenSkipped(string reason);

    function _reopenPositionAfterWithdrawal(int24 tickLower, int24 tickUpper) private {
        (address token0, address token1) = _sortedTokens();
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        // Nothing left (or just dust) — nothing to reopen with, leave it
        // as is, the keeper will pick it up and fold it into the position
        // on its next cycle.
        if (balance0 == 0 && balance1 == 0) {
            emit ReopenSkipped("no balance left to reopen with");
            return;
        }

        (uint160 sqrtPriceX96Spot, , , , , , ) = pool.slot0();
        uint128 liquidity = _getLiquidityForAmounts(
            sqrtPriceX96Spot,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            balance0,
            balance1
        );
        if (liquidity == 0) {
            // Real-world case that prompted adding this event: after a
            // withdrawal payout left the vault holding almost entirely one
            // token (e.g. ~$19.56 in WETH against ~$0 USDC), reusing the
            // OLD range (built for a more balanced composition) can price
            // out to zero achievable liquidity — nothing was wrong, the
            // leftover just didn't fit that particular range well. The
            // keeper's next real rebalance picks a fresh range that does.
            emit ReopenSkipped("computed liquidity is zero for this range");
            return;
        }

        (uint256 expected0, uint256 expected1) = _getAmountsForLiquidity(
            sqrtPriceX96Spot,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidity
        );
        uint256 amount0Min = (expected0 * (10000 - WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS)) / 10000;
        uint256 amount1Min = (expected1 * (10000 - WITHDRAWAL_SLIPPAGE_TOLERANCE_BPS)) / 10000;

        if (IERC20(token0).allowance(address(this), address(positionManager)) < balance0) {
            IERC20(token0).forceApprove(address(positionManager), balance0);
        }
        if (IERC20(token1).allowance(address(this), address(positionManager)) < balance1) {
            IERC20(token1).forceApprove(address(positionManager), balance1);
        }

        try positionManager.mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: poolFee,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0Desired: balance0,
                amount1Desired: balance1,
                amount0Min: amount0Min,
                amount1Min: amount1Min,
                recipient: address(this),
                deadline: block.timestamp
            })
        ) returns (uint256 newTokenId, uint128, uint256 amount0, uint256 amount1) {
            currentPositionTokenId = newTokenId;
            emit Rebalanced(0, newTokenId, tickLower, tickUpper, amount0, amount1);
        } catch Error(string memory reason) {
            // Uniswap's "Price slippage check" and similar require()-based
            // reverts land here, with the actual human-readable reason
            // instead of a blank catch swallowing it.
            emit ReopenSkipped(reason);
        } catch {
            // Custom errors, panics (e.g. arithmetic), or any other revert
            // shape without a plain string reason.
            emit ReopenSkipped("mint reverted with no readable reason");
        }
    }

    /// @notice Alternative to withdraw() that never reverts due to a
    ///         temporary USDC shortfall — if idle USDC (after closing the
    ///         position, same as withdraw() does) isn't enough to cover the
    ///         full `assets` requested, pays the remainder in WETH at the
    ///         pool's 20-minute TWAP price, in the SAME transaction, instead
    ///         of requiring the user to wait for the position to naturally
    ///         drift back into majority USDC.
    /// @dev Security audit finding #4a fix (real-world case that prompted
    ///      this: a user's $19 position closed to $16 USDC + $3-equivalent
    ///      WETH, and plain withdraw() could only ever pay the USDC part —
    ///      the WETH portion had no path out of the contract at all until
    ///      market conditions happened to flip the composition back).
    ///      Standard withdraw()/redeem() are left completely untouched —
    ///      external integrators expecting strict single-asset ERC-4626
    ///      behavior still get it exactly as before. This is simply the
    ///      path the site itself calls by default, since real depositors
    ///      value getting their full value back in one transaction over
    ///      strict standard compliance; anyone who'd rather wait and get
    ///      paid in pure USDC can still call withdraw() instead — their
    ///      choice to make, not one this contract makes for them.
    ///
    ///      NOTE on standard withdraw()/redeem(): the same share-timing
    ///      subtlety fixed below (audit finding #2, round 3) exists there
    ///      too in principle — OpenZeppelin's own public withdraw()/redeem()
    ///      compute shares via previewWithdraw() BEFORE calling our
    ///      _withdraw() override, where the position-closing side effect
    ///      lives. Left as-is deliberately: fixing it there would mean
    ///      overriding OZ's own public entry points, moving further from
    ///      standard ERC-4626 behavior for a discrepancy that's already
    ///      small (only matters when a close is actually triggered, and
    ///      only by the gap between pre- and post-fee totalAssets()).
    ///      A candidate for a future round if this is judged worth the
    ///      added non-conformance.
    function withdrawMixed(uint256 assets, address receiver, address owner_)
        external
        nonReentrant
        returns (uint256 shares)
    {
        _enforceWithdrawalCooldown(owner_);

        uint256 maxAssets = maxWithdraw(owner_);
        if (assets > maxAssets) {
            revert ERC4626ExceededMaxWithdraw(owner_, assets, maxAssets);
        }

        uint256 idleUsdc = IERC20(asset()).balanceOf(address(this));
        bool closedPosition = false;
        int24 closedTickLower;
        int24 closedTickUpper;
        if (idleUsdc < assets && currentPositionTokenId != 0) {
            (closedTickLower, closedTickUpper, closedPosition) = _closeCurrentPositionWithOnChainSlippageProtection();
            idleUsdc = IERC20(asset()).balanceOf(address(this));
        }

        // shares is computed AFTER any position close (security audit
        // round 3, finding #2) — closing pays a performance fee out to
        // feeRecipient and settles previously-stale accrued yield into
        // totalAssets(), both of which change the share price. Computing
        // shares against the pre-close totalAssets() would burn a slightly
        // wrong number of shares relative to the post-close reality; using
        // the fresh value here keeps the burned amount accurate.
        shares = previewWithdraw(assets);

        if (msg.sender != owner_) {
            _spendAllowance(owner_, msg.sender, shares);
        }

        _adjustCostBasisForWithdrawal(owner_, shares);
        _settleYieldBefore(owner_);
        _burn(owner_, shares);
        _resetYieldDebtAfter(owner_);

        if (idleUsdc >= assets) {
            // Security audit finding L004: guard against a zero-value
            // transfer (harmless no-op for USDC/WETH, but a wasted external
            // call/gas if `assets` happens to be 0 — same pattern already
            // used for the idleUsdc branch just below).
            if (assets > 0) IERC20(asset()).safeTransfer(receiver, assets);
        } else {
            uint256 usdcShortfall = assets - idleUsdc;
            uint256 wethNeeded = _usdcToWeth(usdcShortfall);
            uint256 wethAvailable = pairToken.balanceOf(address(this));
            // Honest revert rather than paying out less than the user asked
            // for — if the vault genuinely doesn't hold enough combined
            // value, that's a real shortfall, not something to paper over.
            if (wethNeeded > wethAvailable) revert InsufficientPoolValue();

            if (idleUsdc > 0) IERC20(asset()).safeTransfer(receiver, idleUsdc);
            if (wethNeeded > 0) pairToken.safeTransfer(receiver, wethNeeded);
        }

        if (closedPosition) {
            _reopenPositionAfterWithdrawal(closedTickLower, closedTickUpper);
        }

        emit Withdraw(msg.sender, receiver, owner_, assets, shares);
    }

    /// @notice Moves the vault's liquidity to a new tick range. Called by the
    ///         keeper bot roughly once an hour. Deliberately does NOT
    ///         re-check the bot's timing/trigger logic (still off-chain,
    ///         that part is still fine to trust the bot with).
    /// @dev Security audit findings #2 and #3 fixed here together:
    ///
    ///      #2 (slippage): amount0Min/amount1Min/deadline used to be
    ///      hardcoded to 0/0/block.timestamp — meaning ANY outsider watching
    ///      the mempool (no keeper key needed) could sandwich this call,
    ///      forcing the vault to add/remove liquidity at a manipulated
    ///      price. Now the bot computes real slippage-tolerant minimums
    ///      off-chain (typically a small % below the expected amounts at
    ///      current price) and a real expiry, passed in here for both the
    ///      close (old position) and open (new position) legs separately,
    ///      since they're different operations with different expected
    ///      amounts.
    ///
    ///      #3 (keeper power): a compromised keeper key could previously
    ///      call rebalance() with something like tickLower=-887272,
    ///      tickUpper=887272 (full-range = zero concentration = capital
    ///      earns essentially nothing — "Denial of Yield", not theft, but
    ///      real harm to depositors). Now both edges must fall within
    ///      RANGE_CHECK_TOLERANCE_TICKS of a SEPARATE, shorter 5-minute
    ///      TWAP — short enough to track an honestly fast-moving market
    ///      without spurious reverts, long enough that moving it requires
    ///      sustained pressure, not one transaction. See the constant's own
    ///      docstring for why ~10% tolerance was chosen.
    function rebalance(
        int24 tickLower,
        int24 tickUpper,
        uint256 closeAmount0Min,
        uint256 closeAmount1Min,
        uint256 openAmount0Min,
        uint256 openAmount1Min,
        uint256 deadline
    ) external nonReentrant onlyKeeper {
        int24 twapTick = _getTwapTick(RANGE_CHECK_TWAP_WINDOW);
        if (
            tickLower < twapTick - RANGE_CHECK_TOLERANCE_TICKS ||
            tickLower > twapTick + RANGE_CHECK_TOLERANCE_TICKS ||
            tickUpper < twapTick - RANGE_CHECK_TOLERANCE_TICKS ||
            tickUpper > twapTick + RANGE_CHECK_TOLERANCE_TICKS
        ) {
            revert RangeTooFarFromTwap();
        }

        uint256 oldTokenId = currentPositionTokenId;

        if (oldTokenId != 0) {
            _closeOldPosition(oldTokenId, closeAmount0Min, closeAmount1Min, deadline);
        }

        (uint256 newTokenId, uint256 amount0, uint256 amount1) =
            _openNewPosition(tickLower, tickUpper, openAmount0Min, openAmount1Min, deadline);

        currentPositionTokenId = newTokenId;

        emit Rebalanced(oldTokenId, newTokenId, tickLower, tickUpper, amount0, amount1);
    }

    /// @dev Split out of rebalance() to keep local-variable counts down in
    ///      each function ("stack too deep" otherwise) — also shared with
    ///      _withdraw() when it needs to dip into the position.
    ///
    ///      Also where the performance fee is taken. IMPORTANT: a plain
    ///      positionManager.positions() read BEFORE any liquidity change
    ///      does NOT return live accrued fees — Uniswap only settles the
    ///      real tokensOwed0/1 amount into storage when the position is
    ///      actually touched (mint/decreaseLiquidity/collect all trigger
    ///      this internally). Confirmed by testing: 12+ real rebalances in
    ///      a row all recorded exactly 0 accrued fees despite Uniswap's own
    ///      UI showing real non-zero uncollected fees on the same position.
    ///
    ///      An earlier version of this fix tried to force-settle fees with
    ///      a zero-liquidity decreaseLiquidity() "poke" beforehand — that
    ///      turned out to be invalid: NonfungiblePositionManager's own
    ///      decreaseLiquidity() has `require(params.liquidity > 0)` as its
    ///      very first line, so a zero-amount call always reverts. Confirmed
    ///      directly in Uniswap's v3-periphery source before settling on
    ///      the fix below — this broke rebalance() entirely for a few hours
    ///      in production before being caught and reverted.
    ///
    ///      Correct fix: decreaseLiquidity() itself already settles real
    ///      fees into tokensOwed as a side effect of removing the full
    ///      liquidity — no separate poke needed. It also RETURNS the exact
    ///      principal amounts (amount0, amount1) being removed.
    ///
    ///      Second-round audit finding: an earlier version of this fix read
    ///      tokensOwed AFTER decreaseLiquidity() and subtracted the returned
    ///      principal to isolate fees — correct under this contract's own
    ///      invariants (every position is freshly minted, always fully
    ///      collected before the next close, so tokensOwed should be 0
    ///      going in), but the auditor pointed out this trusts Uniswap's
    ///      internal accounting rather than ground truth: if that invariant
    ///      were ever violated by so much as 1 wei of rounding, the fee
    ///      calculation could exceed what's actually available, permanently
    ///      reverting every future rebalance() (insufficient balance for
    ///      the fee transfer + new position). Fixed by measuring the
    ///      CONTRACT'S OWN real ERC20 balance change across decreaseLiquidity()
    ///      + collect() instead of reading Uniswap's internal tokensOwed at
    ///      all — the fee amount computed this way can mathematically never
    ///      exceed what's physically sitting in the contract, regardless of
    ///      any Uniswap-side accounting subtlety we haven't considered.
    ///
    ///      amount0Min/amount1Min/deadline (security audit finding #2 fix):
    ///      passed through from the caller rather than hardcoded to 0/
    ///      block.timestamp — rebalance() gets these from the keeper bot's
    ///      own off-chain calculation; withdraw()/withdrawMixed() compute a
    ///      modest on-chain minimum themselves (see their call sites).
    function _closeOldPosition(uint256 oldTokenId, uint256 amount0Min, uint256 amount1Min, uint256 deadline) private {
        (, , , , , , , uint128 liquidity, , , , ) = positionManager.positions(oldTokenId);

        uint256 principal0;
        uint256 principal1;

        if (liquidity > 0) {
            (principal0, principal1) = positionManager.decreaseLiquidity(
                INonfungiblePositionManager.DecreaseLiquidityParams({
                    tokenId: oldTokenId,
                    liquidity: liquidity,
                    amount0Min: amount0Min,
                    amount1Min: amount1Min,
                    deadline: deadline
                })
            );
        }

        (address token0, address token1) = _sortedTokens();
        uint256 balance0Before = IERC20(token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(token1).balanceOf(address(this));

        positionManager.collect(
            INonfungiblePositionManager.CollectParams({
                tokenId: oldTokenId,
                recipient: address(this),
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            })
        );

        // The contract's own real balance change — ground truth, not
        // Uniswap's internal accounting. The fee physically cannot exceed
        // what actually landed on the balance.
        uint256 totalReceived0 = IERC20(token0).balanceOf(address(this)) - balance0Before;
        uint256 totalReceived1 = IERC20(token1).balanceOf(address(this)) - balance1Before;

        uint256 feeAmount0Gross = totalReceived0 > principal0 ? totalReceived0 - principal0 : 0;
        uint256 feeAmount1Gross = totalReceived1 > principal1 ? totalReceived1 - principal1 : 0;

        uint256 feeAmount0 = (feeAmount0Gross * performanceFeeBps) / 10000;
        uint256 feeAmount1 = (feeAmount1Gross * performanceFeeBps) / 10000;

        // Gross yield from liquidity provision — 100% of what accrued,
        // before the service's fee cut. This is the number meant to be
        // shown publicly on the site — not what goes to feeRecipient.
        if (feeAmount0Gross > 0 || feeAmount1Gross > 0) {
            uint256 yieldUsdcGross;
            uint256 yieldWethGross;
            uint256 serviceFeeUsdc;
            uint256 serviceFeeWeth;
            if (assetIsToken0) {
                yieldUsdcGross = feeAmount0Gross;
                yieldWethGross = feeAmount1Gross;
                serviceFeeUsdc = feeAmount0;
                serviceFeeWeth = feeAmount1;
            } else {
                yieldWethGross = feeAmount0Gross;
                yieldUsdcGross = feeAmount1Gross;
                serviceFeeWeth = feeAmount0;
                serviceFeeUsdc = feeAmount1;
            }

            totalYieldEarnedUsdc += yieldUsdcGross;
            totalYieldEarnedWeth += yieldWethGross;

            // Growing "yield per share" index — security audit finding #2
            // (round 3): NOT the same gross figure as totalYieldEarnedUsdc/
            // Weth above — the service's cut physically leaves for
            // feeRecipient and leaves the vault, so the personal-facing
            // figure must be the NET yield (after that cut), otherwise
            // personalFeesEarnedUsdValue() would show the user money they
            // can't fully withdraw — part of it is no longer in totalAssets().
            uint256 supply = totalSupply();
            if (supply > 0) {
                uint256 yieldUsdcNet = yieldUsdcGross - serviceFeeUsdc;
                uint256 yieldWethNet = yieldWethGross - serviceFeeWeth;
                accYieldPerShareUsdc += (yieldUsdcNet * YIELD_PRECISION) / supply;
                accYieldPerShareWeth += (yieldWethNet * YIELD_PRECISION) / supply;
            }
        }

        // Security audit finding: feeRecipient was a single point of
        // failure on the critical path. Previously safeTransfer() here
        // reverted the ENTIRE transaction on failure — and closing the
        // position is needed for almost any withdrawal (whenever idle USDC
        // is short), so a broken or maliciously-set feeRecipient (e.g. a
        // contract that always reverts on receiving tokens — whether
        // deliberately, via a compromised owner key, or just by mistake
        // when rotating the address) would paralyze withdrawals for
        // EVERY user at once, until the owner intervened. Now a failed
        // fee transfer blocks nothing — the amount simply stays on the
        // vault's own balance (not lost, reinvested along with everything
        // else), and totalFeesCollectedUsdc/Weth only grows by what was
        // actually sent, not by what "should have" gone out.
        if (feeAmount0 > 0 || feeAmount1 > 0) {
            bool sent0 = feeAmount0 == 0 || _tryTransferFee(token0, feeAmount0);
            bool sent1 = feeAmount1 == 0 || _tryTransferFee(token1, feeAmount1);

            if (assetIsToken0) {
                if (sent0) totalFeesCollectedUsdc += feeAmount0;
                if (sent1) totalFeesCollectedWeth += feeAmount1;
            } else {
                if (sent0) totalFeesCollectedWeth += feeAmount0;
                if (sent1) totalFeesCollectedUsdc += feeAmount1;
            }

            emit PerformanceFeeCollected(sent0 ? feeAmount0 : 0, sent1 ? feeAmount1 : 0);
        }
    }

    /// @dev The external transfer() call is wrapped in try/catch directly
    ///      (not via safeTransfer()) — Solidity's try/catch can only wrap a
    ///      direct external call, not a library wrapper on top of one. For
    ///      USDC/WETH (both standard, correctly bool-returning tokens) this
    ///      doesn't give up the protection safeTransfer() provides
    ///      specifically for NON-standard tokens — it wasn't needed here.
    ///
    ///      Static-analysis note: linters commonly flag a raw ERC-20
    ///      transfer() call like this as "unchecked transfer" — that
    ///      warning is a false positive here specifically. This contract
    ///      only ever calls this with USDC or WETH (see the constructor —
    ///      both are fixed at deployment, never arbitrary user-supplied
    ///      tokens), and both are standard, well-audited implementations
    ///      that always either return true on success or revert — neither
    ///      silently returns false. The return value IS checked and
    ///      correctly acted on regardless: totalFeesCollectedUsdc/Weth are
    ///      only incremented when the transfer actually succeeded (see
    ///      sent0/sent1 at the call site above) — a failure here is fully
    ///      handled, not ignored, it just doesn't revert the whole
    ///      transaction (see this function's caller for why that matters).
    ///      Using SafeERC20.safeTransfer() instead is not possible at this
    ///      specific call site: it's an internal library function (jumped
    ///      to, not DELEGATECALL'd), and Solidity's try/catch only wraps
    ///      genuine external calls or contract creation — wrapping
    ///      safeTransfer() in try/catch simply doesn't compile.
    function _tryTransferFee(address token, uint256 amount) private returns (bool sent) {
        try IERC20(token).transfer(feeRecipient, amount) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev Also split out for the same stack-depth reason — mints a fresh
    ///      position from whatever the vault currently holds.
    ///      amount0Min/amount1Min/deadline (security audit finding #2 fix):
    ///      previously hardcoded to 0/0/block.timestamp, letting anyone
    ///      watching the mempool sandwich this mint() at a manipulated
    ///      price. Now passed through from the caller — see rebalance()'s
    ///      own docstring for where these come from.
    function _openNewPosition(int24 tickLower, int24 tickUpper, uint256 amount0Min, uint256 amount1Min, uint256 deadline)
        private
        returns (uint256 newTokenId, uint256 amount0, uint256 amount1)
    {
        (address token0, address token1) = _sortedTokens();

        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        // Skip approve() entirely if the current allowance is already
        // sufficient (round 3 audit, gas finding #3) — since we no longer
        // reset allowance to 0 after mint() (round 2), leftover from the
        // previous cycle is often already enough, especially for the side
        // that isn't usually fully consumed in our single-sided ranges.
        // Cheap allowance() read instead of an expensive approve() when
        // it's not even needed.
        if (IERC20(token0).allowance(address(this), address(positionManager)) < balance0) {
            IERC20(token0).forceApprove(address(positionManager), balance0);
        }
        if (IERC20(token1).allowance(address(this), address(positionManager)) < balance1) {
            IERC20(token1).forceApprove(address(positionManager), balance1);
        }

        (newTokenId, , amount0, amount1) = positionManager.mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: poolFee,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0Desired: balance0,
                amount1Desired: balance1,
                amount0Min: amount0Min,
                amount1Min: amount1Min,
                recipient: address(this),
                deadline: deadline
            })
        );

        // Don't reset the approval back to 0 here (used to) — per the
        // round-2 audit note: forceApprove() already knows how to correctly
        // rewrite the approval on the NEXT call (tries a direct approve()
        // to the new value first, and only falls back to resetting via 0 if
        // the token doesn't allow that — exactly the scenario forceApprove
        // exists for in the first place). The manual reset here was a pure
        // gas cost (~5-10k per rebalance) with no additional protection
        // beyond what forceApprove already guarantees on the next call.
    }

    /// @dev Security audit finding M002 (independent, second review):
    ///      OpenZeppelin's ERC4626 has built-in "virtual shares" protection
    ///      against the classic inflation/donation attack (an attacker
    ///      mints a tiny amount of shares, then donates a large raw token
    ///      amount directly to the vault's balance — bypassing any price
    ///      logic entirely, since balanceOf() just reads real token balance
    ///      — to skew the exchange rate against the next depositor). That
    ///      protection is controlled by _decimalsOffset(), defaulting to 0
    ///      (minimal but non-zero protection) unless overridden. Left at
    ///      the default since the project's very first security review —
    ///      that review's TWAP fix (see totalAssets() below) protects
    ///      against PRICE manipulation of the WETH portion specifically,
    ///      but a raw donation attack against idle USDC/WETH balances is a
    ///      genuinely separate vector TWAP doesn't touch at all. A non-zero
    ///      offset makes the attack exponentially more expensive without
    ///      changing any user-visible behavior — shares (CRK) are
    ///      deliberately never displayed on the site at all, only their
    ///      USD-equivalent value via convertToAssets() (which stays in
    ///      asset() decimals — USDC's 6 — regardless of this offset), so
    ///      there's no display assumption anywhere to break.
    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }

    /// @notice Total vault value, expressed in `asset()` (USDC) — the number
    ///         ERC4626 uses to price shares on every deposit/withdraw.
    /// @dev Sums three things: idle USDC sitting on the contract, idle WETH
    ///      (converted via the pool's current price), and the open Uniswap
    ///      V3 position's principal + uncollected fees (also converted).
    ///      Uses a 20-minute TWAP (security audit finding #1 fix — this used
    ///      to read pool.slot0(), the spot price, which is manipulable
    ///      within a single transaction/block via flash loan or large swap,
    ///      including a donation-style attack against share pricing on
    ///      deposit/withdraw). A 20-minute window requires sustained price
    ///      pressure over real time to move, not a single transaction.
    function totalAssets() public view override returns (uint256) {
        uint256 idleUsdc = IERC20(asset()).balanceOf(address(this));
        uint256 idleWeth = pairToken.balanceOf(address(this));

        (uint256 positionUsdc, uint256 positionWeth) = _positionValue();

        uint256 totalWeth = idleWeth + positionWeth;
        uint256 wethValueInUsdc = totalWeth == 0 ? 0 : _wethToUsdc(totalWeth);

        return idleUsdc + positionUsdc + wethValueInUsdc;
    }

    /// @notice Full breakdown of vault value — how much USDC, how much WETH,
    ///         each in its own native units (not converted). Adds idle
    ///         balances (sitting directly on the contract) to whatever's in
    ///         the open Uniswap position. Reuses the same _positionValue()
    ///         that totalAssets() already relies on — no new math, just a
    ///         different way of reading the same numbers, for the site to
    ///         show "X USDC / Y ETH" instead of one combined dollar figure.
    function vaultBalances() external view returns (uint256 usdcAmount, uint256 wethAmount) {
        uint256 idleUsdc = IERC20(asset()).balanceOf(address(this));
        uint256 idleWeth = pairToken.balanceOf(address(this));
        (uint256 positionUsdc, uint256 positionWeth) = _positionValue();
        usdcAmount = idleUsdc + positionUsdc;
        wethAmount = idleWeth + positionWeth;
    }

    /// @notice Cumulative performance fees ever sent to feeRecipient,
    ///         expressed as one USD-equivalent figure (the WETH portion
    ///         converted at the pool's current price). This is the
    ///         SERVICE'S cut — NOT meant to be shown publicly on the site;
    ///         use totalYieldEarnedUsdValue() below for that instead.
    function totalFeesCollectedUsdValue() external view returns (uint256) {
        return totalFeesCollectedUsdc + (totalFeesCollectedWeth == 0 ? 0 : _wethToUsdc(totalFeesCollectedWeth));
    }

    /// @notice Cumulative GROSS yield ever earned from providing liquidity
    ///         (100% of accrued trading fees, before the service's cut),
    ///         expressed as one USD-equivalent figure — this is the number
    ///         meant to be shown on the site as "fees earned" for depositors.
    function totalYieldEarnedUsdValue() external view returns (uint256) {
        return totalYieldEarnedUsdc + (totalYieldEarnedWeth == 0 ? 0 : _wethToUsdc(totalYieldEarnedWeth));
    }

    /// @notice A specific user's personal profit — the current value of
    ///         their shares minus their costBasis (proportionally-adjusted
    ///         cost basis — see costBasis's own docstring). Can be negative
    ///         (int256, not uint256) — for example, if the position hasn't
    ///         covered gas yet, or has temporarily dipped in price.
    function personalProfit(address user) external view returns (int256) {
        uint256 currentValue = convertToAssets(balanceOf(user));
        return int256(currentValue) - int256(costBasis[user]);
    }

    /// @notice A specific user's personal income from providing liquidity
    ///         (trading fees), as a single USD-equivalent figure —
    ///         INDEPENDENT of ETH price movement, unlike personalProfit()
    ///         above (see accYieldPerShareUsdc/Weth's own docstring).
    ///         Includes the already-settled portion (personalYieldEarnedUsdc/
    ///         Weth) plus the not-yet-settled (pending) part since the last
    ///         checkpoint — the number is live, updating between
    ///         transactions, not only at the moment they occur. This is
    ///         what's meant to be shown on the site as "Earned in fees,
    ///         since your first deposit" — the personal counterpart to
    ///         totalYieldEarnedUsdValue().
    function personalFeesEarnedUsdValue(address user) external view returns (uint256) {
        uint256 bal = balanceOf(user);
        uint256 pendingUsdc = bal > 0 ? (bal * accYieldPerShareUsdc) / YIELD_PRECISION - _yieldDebtUsdc[user] : 0;
        uint256 pendingWeth = bal > 0 ? (bal * accYieldPerShareWeth) / YIELD_PRECISION - _yieldDebtWeth[user] : 0;

        uint256 totalUsdc = personalYieldEarnedUsdc[user] + pendingUsdc;
        uint256 totalWeth = personalYieldEarnedWeth[user] + pendingWeth;

        return totalUsdc + (totalWeth == 0 ? 0 : _wethToUsdc(totalWeth));
    }

    /// @dev Split out of totalAssets() specifically to avoid a "stack too
    ///      deep" compiler error — positions() alone returns 12 fields, and
    ///      keeping that live alongside totalAssets()'s other variables
    ///      exceeded the EVM's local-variable stack limit. Each function call
    ///      gets its own fresh stack, so splitting the work (rather than
    ///      switching on the --via-ir compiler flag) fixes it without
    ///      changing any of the actual math.
    function _positionValue() private view returns (uint256 positionUsdc, uint256 positionWeth) {
        uint256 tokenId = currentPositionTokenId;
        if (tokenId == 0) return (0, 0);

        (, , , , , int24 tickLower, int24 tickUpper, uint128 liquidity, , , uint128 tokensOwed0, uint128 tokensOwed1) =
            positionManager.positions(tokenId);

        if (liquidity > 0) {
            (uint256 amount0, uint256 amount1) = _liquidityValue(tickLower, tickUpper, liquidity);
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

    /// @dev Also split out for the same stack-depth reason — isolates the
    ///      TWAP read and the tick->sqrtPrice conversions from everything
    ///      else in _positionValue().
    ///      Security audit finding #1 fix: previously read pool.slot0()
    ///      (spot price), manipulable within a single block/transaction.
    ///      Now uses the 20-minute TWAP (TOTAL_ASSETS_TWAP_WINDOW) instead —
    ///      moving THIS price meaningfully requires sustained pressure over
    ///      real time, not a single flash-loan-funded transaction.
    function _liquidityValue(int24 tickLower, int24 tickUpper, uint128 liquidity)
        private
        view
        returns (uint256 amount0, uint256 amount1)
    {
        uint160 sqrtPriceX96 = _getTwapSqrtPriceX96(TOTAL_ASSETS_TWAP_WINDOW);
        return _getAmountsForLiquidity(
            sqrtPriceX96,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidity
        );
    }

    function _sortedTokens() private view returns (address token0, address token1) {
        return assetIsToken0
            ? (address(asset()), address(pairToken))
            : (address(pairToken), address(asset()));
    }

    /// @dev Time-weighted-average tick over the given window, read from the
    ///      pool's own observation buffer. Formula matches Uniswap's own
    ///      OracleLibrary.consult() exactly (verified against
    ///      v3-periphery/contracts/libraries/OracleLibrary.sol before
    ///      writing this) — several other protocols have shipped audit
    ///      findings specifically from getting the negative-delta rounding
    ///      direction wrong here, so this isn't reinvented casually.
    ///      Reverts if the pool's observation buffer doesn't hold data this
    ///      far back (e.g. a freshly deployed pool) — failing loudly beats
    ///      silently falling back to spot price, which would quietly reopen
    ///      the exact manipulation this exists to close.
    ///
    ///      DEPLOYMENT NOTE (security audit, round 2): this WILL revert with
    ///      Uniswap's "OLD" error on a low-activity or freshly-created pool
    ///      whose observation buffer hasn't accumulated TOTAL_ASSETS_TWAP_WINDOW
    ///      (20 min) of history yet — e.g. testnets, or a brand new pool on
    ///      any network. Not a risk for THIS deployment (the real mainnet
    ///      WETH/USDC 0.05% pool has $75M+ TVL and deep observation history
    ///      already), but if this contract is ever redeployed against a
    ///      different/newer pool: call pool.increaseObservationCardinalityNext()
    ///      first, and let at least one real trade happen and 20 minutes
    ///      pass before the first deposit, or every totalAssets()/rebalance()
    ///      call will simply revert.
    function _getTwapTick(uint32 secondsAgo) private view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = secondsAgo;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int256 avgTickWide = tickCumulativesDelta / int56(uint56(secondsAgo));

        // Security audit finding L001 (same class as the liquidity casts
        // below) — real pool ticks are always within Uniswap's own
        // MIN_TICK/MAX_TICK bounds (±887272, well inside int24's range),
        // and a TWAP is just an average of real ticks, so this should
        // never actually trigger — explicit check costs nothing and closes
        // the theoretical gap rather than silently wrapping.
        //
        // NOTE on the bound used here: this checks against int24's own
        // TYPE range (±8,388,608), not Uniswap's tighter protocol MIN_TICK/
        // MAX_TICK (±887,272) — deliberately. The gap between them means
        // this wouldn't catch a nonsensical-but-in-range value, but that
        // gap is only reachable from a pool lying about its own tick data
        // in the first place (this contract is scoped to genuine, canonical
        // Uniswap V3 pools among top-liquidity pairs — see the contract's
        // own top-level docstring), which is a different, broader threat
        // model a tick bounds check wouldn't meaningfully address anyway.
        // Also worth noting: the avgTick-- decrement a few lines below is
        // safe even at Uniswap's real MIN_TICK (-887272 - 1 is nowhere near
        // int24's actual underflow boundary) — the type-level check above
        // is about closing a theoretical casting gap, unrelated to that
        // decrement's own safety.
        if (avgTickWide > int256(int24(type(int24).max)) || avgTickWide < int256(int24(type(int24).min))) {
            revert TickOverflow();
        }
        int24 avgTick = int24(avgTickWide);

        // Always round to negative infinity, matching Uniswap's own
        // OracleLibrary — Solidity's integer division rounds toward zero,
        // which is the wrong direction for a negative delta.
        if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(uint56(secondsAgo)) != 0)) {
            avgTick--;
        }

        return avgTick;
    }

    /// @dev TWAP tick converted to a sqrtPriceX96, for direct use anywhere
    ///      the code previously read pool.slot0()'s spot price for
    ///      VALUATION purposes. NOT used for the keeper's own range-setting
    ///      decision — that intentionally stays on live slot0() in the
    ///      off-chain bot (security audit finding #1's fix applies to
    ///      totalAssets()'s share pricing, not to rebalance()'s execution,
    ///      which amount0Min/amount1Min protect instead — see rebalance()).
    function _getTwapSqrtPriceX96(uint32 secondsAgo) private view returns (uint160) {
        return TickMath.getSqrtPriceAtTick(_getTwapTick(secondsAgo));
    }

    /// @dev Converts a raw WETH amount into its USDC-equivalent using the
    ///      20-minute TWAP (security audit finding #1 fix — was spot price).
    function _wethToUsdc(uint256 wethAmount) private view returns (uint256) {
        uint160 sqrtPriceX96 = _getTwapSqrtPriceX96(TOTAL_ASSETS_TWAP_WINDOW);

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

    /// @dev Reverse of _wethToUsdc() — needed by withdrawMixed() to know how
    ///      much WETH covers a given USDC shortfall. Same TWAP source, same
    ///      manipulation-resistance rationale.
    function _usdcToWeth(uint256 usdcAmount) private view returns (uint256) {
        uint160 sqrtPriceX96 = _getTwapSqrtPriceX96(TOTAL_ASSETS_TWAP_WINDOW);
        uint256 priceX96 = FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), Q96);

        if (assetIsToken0) {
            return FullMath.mulDiv(usdcAmount, priceX96, Q96);
        } else {
            return FullMath.mulDiv(usdcAmount, Q96, priceX96);
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

    // ---- Reverse problem: how much liquidity is actually achievable from
    // the amounts on hand ---- (LiquidityAmounts.getLiquidityForAmounts, the
    // same port already done for the bot in bot/tickMath.js — an on-chain
    // version is also needed here for _reopenPositionAfterWithdrawal(),
    // which has no bot feeding it ready-made numbers).
    //
    // Security audit finding L001: narrowing uint256 -> uint128 silently
    // "wraps" (truncates) on its own if the result exceeds uint128's limit
    // — Solidity doesn't check this automatically for explicit type casts
    // (unlike arithmetic, where overflow is caught on its own). In practice
    // the result reaching here comes from FullMath.mulDiv at realistic
    // vault sizes (computed separately — overflow would require on the
    // order of $10^24, astronomically unreachable), but the explicit check
    // costs nothing and closes even the theoretical risk entirely — the
    // same technique Uniswap itself uses in its own toUint128().
    function _toUint128(uint256 value) private pure returns (uint128) {
        if (value > type(uint128).max) revert LiquidityOverflow();
        return uint128(value);
    }

    function _getLiquidityForAmount0(uint160 sqrtRatioAX96, uint160 sqrtRatioBX96, uint256 amount0)
        private
        pure
        returns (uint128 liquidity)
    {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        uint256 intermediate = FullMath.mulDiv(sqrtRatioAX96, sqrtRatioBX96, FixedPoint96.Q96);
        return _toUint128(FullMath.mulDiv(amount0, intermediate, sqrtRatioBX96 - sqrtRatioAX96));
    }

    function _getLiquidityForAmount1(uint160 sqrtRatioAX96, uint160 sqrtRatioBX96, uint256 amount1)
        private
        pure
        returns (uint128 liquidity)
    {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        return _toUint128(FullMath.mulDiv(amount1, FixedPoint96.Q96, sqrtRatioBX96 - sqrtRatioAX96));
    }

    function _getLiquidityForAmounts(
        uint160 sqrtRatioX96,
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint256 amount0,
        uint256 amount1
    ) private pure returns (uint128 liquidity) {
        if (sqrtRatioAX96 > sqrtRatioBX96) (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);

        if (sqrtRatioX96 <= sqrtRatioAX96) {
            liquidity = _getLiquidityForAmount0(sqrtRatioAX96, sqrtRatioBX96, amount0);
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            uint128 liquidity0 = _getLiquidityForAmount0(sqrtRatioX96, sqrtRatioBX96, amount0);
            uint128 liquidity1 = _getLiquidityForAmount1(sqrtRatioAX96, sqrtRatioX96, amount1);
            liquidity = liquidity0 < liquidity1 ? liquidity0 : liquidity1;
        } else {
            liquidity = _getLiquidityForAmount1(sqrtRatioAX96, sqrtRatioBX96, amount1);
        }
    }
}