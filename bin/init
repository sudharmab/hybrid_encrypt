#!/usr/bin/env python3
import sys
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def write_key_file(path, keys):
    with open(path, 'w') as f:
        for label, content in keys.items():
            if content.startswith("-----"):
                #print(f"Writing PEM key to {path}: {label}")
                f.write(content + "\n")
            else:
                #print(f"Writing label to {path}: {label}={content}")
                f.write(f"{label}={content}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: init <filename>")
        sys.exit(62)

    filename = sys.argv[1]
    atm_file = filename + ".atm"
    bank_file = filename + ".bank"

    if os.path.exists(atm_file) or os.path.exists(bank_file):
        print("Error: one of the files already exists")
        sys.exit(63)

    try:
        # Generate the pub/priv keys and symmetric keys as needed
        bank_key = RSA.generate(2048)
        atm_key = RSA.generate(2048)
        aes_key = get_random_bytes(32)  # AES-256

        # allow to export keys
        bank_priv = bank_key.export_key().decode()
        bank_pub = bank_key.publickey().export_key().decode()
        atm_priv = atm_key.export_key().decode()
        atm_pub = atm_key.publickey().export_key().decode()
        aes_key_b64 = base64.b64encode(aes_key).decode()

        # Write .bank (bank's private key, ATM's pubkey, AES key)
        write_key_file(bank_file, {
            "BANK_PRIVATE_KEY": bank_priv,
            "ATM_PUBLIC_KEY": atm_pub,
            "AES_KEY": aes_key_b64
     })

        # Write .atm (bank's public key, ATM's private key, AES key)
        write_key_file(atm_file, {
            "BANK_PUBLIC_KEY": bank_pub,
            "ATM_PRIVATE_KEY": atm_priv,
            "AES_KEY": aes_key_b64
        })

    except Exception as e:
        print("Error during initialization:", e)
        sys.exit(64)

    print("Successfully initialized bank state")
    sys.exit(0)

if __name__ == "__main__":
    main()

