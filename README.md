# RustChain Wallet CLI

Command-line tool for managing RTC tokens on RustChain.

## Install

```bash
pip install git+https://github.com/EugeneJarvis88/rustchain-wallet-cli.git
```

## Commands

```bash
# Create new wallet
rustchain-wallet create

# Import from seed phrase
rustchain-wallet import "word1 word2 ... word24"

# List wallets
rustchain-wallet list

# Check balance
rustchain-wallet balance <wallet-id>

# Send RTC
rustchain-wallet send <to-address> <amount> --wallet <name>

# Export keystore
rustchain-wallet export <wallet-name>

# Network info
rustchain-wallet miners
rustchain-wallet epoch
```

## Features

- ✅ BIP39 24-word seed phrases
- ✅ AES-256-GCM encrypted keystores
- ✅ Ed25519 signing
- ✅ Password-protected keys
- ✅ Linux & macOS support

## Bounty

[#39](https://github.com/Scottcjn/rustchain-bounties/issues/39) - 50 RTC

Wallet: `zARG9WZCiRRzghuCzx1kqSynhYanBnGdjfz4kjSjvin`
