#!/usr/bin/env python3
"""
RustChain Wallet CLI
Command-line tool for managing RTC tokens
"""

import os
import sys
import json
import hashlib
import secrets
import getpass
import argparse
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    import httpx
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependencies. Install with: pip install httpx cryptography")
    sys.exit(1)


# Config
WALLET_DIR = Path.home() / ".rustchain" / "wallets"
NODE_URL = "https://50.28.86.131"

# BIP39 wordlist (simplified - first 256 words)
BIP39_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
]


@dataclass
class WalletData:
    """Wallet data structure"""
    address: str
    public_key: str
    encrypted_key: str
    salt: str
    nonce: str
    created_at: str
    version: int = 1


def generate_mnemonic(word_count: int = 24) -> str:
    """Generate BIP39 mnemonic phrase"""
    entropy = secrets.token_bytes(word_count * 4 // 3)
    indices = [b % len(BIP39_WORDS) for b in entropy]
    return " ".join(BIP39_WORDS[i] for i in indices[:word_count])


def mnemonic_to_seed(mnemonic: str) -> bytes:
    """Convert mnemonic to seed bytes"""
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"rustchain", 2048)[:32]


def derive_keypair(seed: bytes) -> tuple:
    """Derive Ed25519-style keypair from seed"""
    private_key = seed
    public_key = hashlib.sha256(private_key).digest()
    return private_key, public_key


def create_address(public_key: bytes, prefix: str = "RTC") -> str:
    """Create wallet address from public key"""
    h = hashlib.sha256(public_key).hexdigest()[:40]
    return f"{prefix}-{h[:8]}-{h[8:16]}-{h[16:24]}-{h[24:32]}"


def encrypt_key(private_key: bytes, password: str) -> tuple:
    """Encrypt private key with password (AES-256-GCM)"""
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    encrypted = aesgcm.encrypt(nonce, private_key, None)
    
    return encrypted, salt, nonce


def decrypt_key(encrypted: bytes, salt: bytes, nonce: bytes, password: str) -> bytes:
    """Decrypt private key with password"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted, None)


def save_wallet(wallet: WalletData, filename: str):
    """Save wallet to encrypted keystore file"""
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    filepath = WALLET_DIR / f"{filename}.json"
    
    with open(filepath, "w") as f:
        json.dump(asdict(wallet), f, indent=2)
    
    os.chmod(filepath, 0o600)
    return filepath


def load_wallet(filename: str) -> WalletData:
    """Load wallet from keystore file"""
    filepath = WALLET_DIR / f"{filename}.json"
    
    if not filepath.exists():
        raise FileNotFoundError(f"Wallet not found: {filepath}")
    
    with open(filepath) as f:
        data = json.load(f)
    
    return WalletData(**data)


def list_wallets() -> list:
    """List all wallet files"""
    if not WALLET_DIR.exists():
        return []
    return [f.stem for f in WALLET_DIR.glob("*.json")]


def api_request(method: str, endpoint: str, **kwargs) -> dict:
    """Make API request to RustChain node"""
    with httpx.Client(verify=False, timeout=30) as client:
        response = client.request(method, f"{NODE_URL}{endpoint}", **kwargs)
        return response.json()


def sign_transfer(private_key: bytes, from_addr: str, to_addr: str, amount: float) -> str:
    """Sign a transfer transaction"""
    import hmac
    nonce = secrets.randbelow(2**32)
    message = f"{from_addr}:{to_addr}:{amount}:{nonce}".encode()
    signature = hmac.new(private_key, message, hashlib.sha256).hexdigest()
    return signature


# CLI Commands

def cmd_create(args):
    """Create new wallet"""
    print("Creating new RustChain wallet...\n")
    
    # Generate mnemonic
    mnemonic = generate_mnemonic(24)
    print("⚠️  SAVE THIS SEED PHRASE SECURELY - IT CANNOT BE RECOVERED!\n")
    print(f"  {mnemonic}\n")
    
    # Derive keys
    seed = mnemonic_to_seed(mnemonic)
    private_key, public_key = derive_keypair(seed)
    address = create_address(public_key)
    
    # Get password
    password = getpass.getpass("Enter password to encrypt wallet: ")
    password2 = getpass.getpass("Confirm password: ")
    
    if password != password2:
        print("❌ Passwords don't match")
        return 1
    
    # Encrypt and save
    encrypted, salt, nonce = encrypt_key(private_key, password)
    
    wallet = WalletData(
        address=address,
        public_key=public_key.hex(),
        encrypted_key=encrypted.hex(),
        salt=salt.hex(),
        nonce=nonce.hex(),
        created_at=datetime.utcnow().isoformat(),
    )
    
    filename = args.name or address.split("-")[1]
    filepath = save_wallet(wallet, filename)
    
    print(f"\n✅ Wallet created!")
    print(f"   Address:  {address}")
    print(f"   Keystore: {filepath}")
    return 0


def cmd_import(args):
    """Import wallet from seed phrase"""
    print("Import wallet from seed phrase\n")
    
    mnemonic = args.seed_phrase or getpass.getpass("Enter seed phrase: ")
    
    seed = mnemonic_to_seed(mnemonic)
    private_key, public_key = derive_keypair(seed)
    address = create_address(public_key)
    
    password = getpass.getpass("Enter password to encrypt wallet: ")
    encrypted, salt, nonce = encrypt_key(private_key, password)
    
    wallet = WalletData(
        address=address,
        public_key=public_key.hex(),
        encrypted_key=encrypted.hex(),
        salt=salt.hex(),
        nonce=nonce.hex(),
        created_at=datetime.utcnow().isoformat(),
    )
    
    filename = args.name or address.split("-")[1]
    filepath = save_wallet(wallet, filename)
    
    print(f"\n✅ Wallet imported!")
    print(f"   Address:  {address}")
    print(f"   Keystore: {filepath}")
    return 0


def cmd_list(args):
    """List all wallets"""
    wallets = list_wallets()
    
    if not wallets:
        print("No wallets found. Create one with: rustchain-wallet create")
        return 0
    
    print(f"Found {len(wallets)} wallet(s):\n")
    
    for name in wallets:
        try:
            wallet = load_wallet(name)
            print(f"  📁 {name}")
            print(f"     Address: {wallet.address}")
        except Exception as e:
            print(f"  📁 {name} (error: {e})")
    
    return 0


def cmd_balance(args):
    """Check wallet balance"""
    wallet_id = args.wallet
    
    try:
        data = api_request("GET", "/wallet/balance", params={"miner_id": wallet_id})
        balance = data.get("balance", 0)
        print(f"Balance: {balance} RTC")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def cmd_send(args):
    """Send RTC to another wallet"""
    wallet = load_wallet(args.wallet)
    password = getpass.getpass("Enter wallet password: ")
    
    try:
        private_key = decrypt_key(
            bytes.fromhex(wallet.encrypted_key),
            bytes.fromhex(wallet.salt),
            bytes.fromhex(wallet.nonce),
            password,
        )
    except Exception:
        print("❌ Invalid password")
        return 1
    
    signature = sign_transfer(private_key, wallet.address, args.to, args.amount)
    
    print(f"\nSending {args.amount} RTC")
    print(f"  From: {wallet.address}")
    print(f"  To:   {args.to}")
    
    try:
        result = api_request("POST", "/wallet/transfer/signed", json={
            "from": wallet.address,
            "to": args.to,
            "amount": args.amount,
            "signature": signature,
        })
        print(f"\n✅ Transfer complete!")
        print(f"   TX: {result.get('tx_id', 'pending')}")
    except Exception as e:
        print(f"❌ Transfer failed: {e}")
        return 1
    
    return 0


def cmd_export(args):
    """Export wallet keystore"""
    wallet = load_wallet(args.wallet)
    print(json.dumps(asdict(wallet), indent=2))
    return 0


def cmd_miners(args):
    """List active miners"""
    try:
        data = api_request("GET", "/api/miners")
        miners = data if isinstance(data, list) else data.get("miners", [])
        
        print(f"Active miners: {len(miners)}\n")
        for m in miners:
            print(f"  🔧 {m.get('miner_id', 'unknown')}")
            print(f"     Hardware: {m.get('hardware', 'unknown')}")
            print(f"     Multiplier: {m.get('multiplier', 1)}x")
            print()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def cmd_epoch(args):
    """Show current epoch info"""
    try:
        data = api_request("GET", "/epoch")
        print(f"Current Epoch: {data.get('epoch', 'unknown')}")
        print(f"Total Rewards: {data.get('total_rewards', 0)} RTC")
        print(f"Active Miners: {data.get('miners_count', 0)}")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="rustchain-wallet",
        description="RustChain Wallet CLI - Manage RTC tokens",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # create
    p_create = subparsers.add_parser("create", help="Create new wallet")
    p_create.add_argument("--name", help="Wallet filename")
    p_create.set_defaults(func=cmd_create)
    
    # import
    p_import = subparsers.add_parser("import", help="Import from seed phrase")
    p_import.add_argument("seed_phrase", nargs="?", help="24-word seed phrase")
    p_import.add_argument("--name", help="Wallet filename")
    p_import.set_defaults(func=cmd_import)
    
    # list
    p_list = subparsers.add_parser("list", help="List wallets")
    p_list.set_defaults(func=cmd_list)
    
    # balance
    p_balance = subparsers.add_parser("balance", help="Check balance")
    p_balance.add_argument("wallet", help="Wallet ID or miner ID")
    p_balance.set_defaults(func=cmd_balance)
    
    # send
    p_send = subparsers.add_parser("send", help="Send RTC")
    p_send.add_argument("to", help="Recipient address")
    p_send.add_argument("amount", type=float, help="Amount to send")
    p_send.add_argument("--wallet", required=True, help="Wallet name")
    p_send.set_defaults(func=cmd_send)
    
    # export
    p_export = subparsers.add_parser("export", help="Export keystore")
    p_export.add_argument("wallet", help="Wallet name")
    p_export.set_defaults(func=cmd_export)
    
    # miners
    p_miners = subparsers.add_parser("miners", help="List active miners")
    p_miners.set_defaults(func=cmd_miners)
    
    # epoch
    p_epoch = subparsers.add_parser("epoch", help="Show epoch info")
    p_epoch.set_defaults(func=cmd_epoch)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
