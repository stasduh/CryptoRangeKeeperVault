# Crypto Range Keeper Vault 🎯⚡

**Crypto Range Keeper Vault** is an automated, non-custodial yield management protocol and Web3 application designed for concentrated liquidity provision (such as Uniswap v3). It continuously monitors concentrated liquidity positions, automatically rebalances out-of-range assets back into optimal earning bands, and auto-compounds trading fees to maximize Capital Efficiency and LP returns.

🌐 **Live Application:** [https://cryptorangekeeper.com](https://cryptorangekeeper.com) 

📂 **GitHub Smart Contract Repository:** [https://github.com/stasduh/CryptoRangeKeeperVault](https://github.com/stasduh/CryptoRangeKeeperVault)

📂 **GitHub Frontend Repository:** [https://github.com/stasduh/CryptoRangeKeeper](https://github.com/stasduh/CryptoRangeKeeper)

---

## 🌟 Key Features

- 🎯 **Automated In-Range Liquidity Management:** Automatically detects when LP positions fall out of range due to market volatility and adjusts position ticks.
- 🔄 **Auto-Compounding Yields:** Periodically collects accumulated trading fees and reinvests them into active liquidity pools for compound interest gains.
- ⚡ **Optimal Gas Execution:** Uses off-chain monitoring triggers paired with secure, gas-efficient smart contract calls to execute rebalances only when economically viable.
- 🛡️ **Non-Custodial & Permissionless:** Users retain full ownership of their underlying tokens. Positions can be withdrawn or adjusted at any time.
- 📊 **Real-Time Analytics Dashboard:** Sleek web interface to track active positions, impermanent loss metrics, accrued fee rewards, and historical vault performance.
- 🔌 **Multi-Wallet Support:** Seamless integration via Wagmi/Viem supporting MetaMask, Coinbase Wallet, WalletConnect, and Rainbow.

---

## 🏗️ Architecture & How It Works

```
01
DApp
HTML5 · ethers.js · Bootstrap 5
Deposits, withdrawals, and yield monitoring. Transactions are signed right in MetaMask / WalletConnect — no backend in between.

→
02
Smart Contract
Solidity · ERC-4626 · Arbitrum One
Tracks each investor's share and holds a single concentrated position via Uniswap V3's NonfungiblePositionManager.

←
03
Keeper Bot
Node.js · Cron · PostgreSQL
Checks the price tick every rebalance(). The database stores only analytics — no keys, no funds.

```

1. **Deposit:** LPs deposit token pairs (e.g., ETH/USDC) into the Range Keeper Vault.
2. **Strategy Allocation:** The vault deploys liquidity into an optimized target price range on concentrated liquidity AMMs.
3. **Continuous Range Monitoring:** Automation bots track oracle prices and pool tick states.
4. **Rebalance & Compound Trigger:** When price strays outside the target range, the vault executes an automated swap & re-mint cycle to place liquidity back into the active fee-earning zone.

---

## 🛡️ Security & Audits

- **Non-Custodial Design:** Smart contracts hold no administrative powers to withdraw user funds directly.
- **Slippage Protection:** All rebalancing swaps enforce maximum acceptable slippage parameters to defend against MEV / sandwich attacks.
- **Reentrancy Protection:** Built with OpenZeppelin's `ReentrancyGuard`.

> **Note:** Software is provided "as is". Use at your own risk when connecting production wallets.

---

## 🗺️ Roadmap

- [x] Initial UI/UX Prototype & Vercel Deployment
- [x] Web3 Wallet Integration 
- [ ] Strategy Customization (Aggressive, Moderate, Conservative Range Widths)
- [ ] Comprehensive Third-Party Smart Contract Audit

---

## 📄 License

This project is open-source and licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Stas Dukh.**
- GitHub: [@stasduh](https://github.com/stasduh)
- Web App: [range-keeper.vercel.app](https://range-keeper.vercel.app/)

---

*Made with ❤️ for DeFi liquidity providers.*
