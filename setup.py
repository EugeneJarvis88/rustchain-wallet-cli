from setuptools import setup, find_packages

setup(
    name="rustchain-wallet-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["httpx", "cryptography"],
    entry_points={
        "console_scripts": [
            "rustchain-wallet=rustchain_wallet.cli:main",
        ],
    },
    python_requires=">=3.8",
)
