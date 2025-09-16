PJ4 Deliverable:
By: Ever Campos, and S
ATM/Bank System Design Document

System Design:

    Overview:
     Our ATM/Bank system is designed to securely handle user authentication, balance inquiries, and withdrawals. The system consists of three main components:

        ATM: Interfaces with the user, processes commands, and communicates securely with the bank.

        Bank: Maintains user accounts, processes commands from the ATM, and ensures secure communication.

        Router: Forwards messages between the ATM and the Bank.



Key Features:

    Authentication:
        - Users authenticate using a .card file and a 4-digit PIN.
        - The ATM securely sends login credentials to the bank for verification.


    Encryption:
        - All communication between the ATM and the bank is encrypted using AES-GCM with a shared AES key.
        - The AES key is securely exchanged during initialization using RSA encryption.


    Integrity:
        - Messages are signed using RSA private keys and verified using RSA public keys to ensure integrity and authenticity.


    Session Management
        - The ATM tracks active sessions to ensure only authenticated users can perform operations.


    Error Handling
        - Invalid commands, insufficient funds, and other errors are handled gracefully with appropriate messages.



Initialization:
    The init program generates:
        - RSA key pairs for the ATM and the bank.
        - A shared symmetric AES key for encrypting communication.
        - .atm and .bank files containing the necessary keys and configuration.



Message Format:

    ATM to Bank:
        - RSA-encrypted AES key
        - AES-GCM-encrypted command
        - AES-GCM tag and IV
        - RSA signature of the encrypted command


    Bank to ATM:
        - AES-GCM-encrypted response
        - AES-GCM tag and IV
        - RSA signature of the encrypted response



Vulnerabilities and Mitigations
1. Replay Attacks
    Vulnerability:
        - An attacker could capture a valid encrypted message (e.g., a withdrawal request) and replay it to the bank.
    Mitigation:
        - Nonce-based system using a random IV for each message.
    Implementation:
        - ATM: Generates a random IV using RAND_bytes.
        - Bank: Maintains a list of previously used IVs and rejects duplicates.

2. Message Tampering
    Vulnerability:
        - An attacker could modify an encrypted message (e.g., the withdrawal amount).
    Mitigation:
        - RSA digital signatures verify message authenticity.
    Implementation:
        - ATM: Signs each message using EVP_DigestSign.
        - Bank: Verifies using EVP_DigestVerify.

3. Key Theft
    Vulnerability:
        - If the AES key is exposed, an attacker could decrypt all communication.
    Mitigation:
        - RSA encryption of AES key during transmission.
    Implementation:
        - ATM: Encrypts AES key using EVP_PKEY_encrypt.
        - Bank: Decrypts using EVP_PKEY_decrypt.



4. Unauthorized Access
    Vulnerability:
        - An attacker could brute-force a user's PIN.
    Mitigation:
        - Login rate limiting.
    Implementation:
        - ATM: Locks session after 3 failed login attempts.
        - Bank: Sends "Not authorized" on invalid attempts.

5. Insufficient Funds Exploit
    Vulnerability:
        - Attacker may attempt to withdraw more than the balance, risking overflow.
    Mitigation:
        - Balance and overflow validation.
    Implementation:
        - Bank: Checks amount against balance and validates to prevent overflow.



6. Eavesdropping
    Vulnerability:
        - Router could intercept and read plaintext messages.
    Mitigation:
        - End-to-end encryption using AES-GCM.
    Implementation:
        - ATM: Encrypts with AES-GCM.
        - Bank: Decrypts with AES-GCM.



7. Invalid Command Injection
    Vulnerability:
        - Malformed commands could crash or destabilize the system.
    Mitigation:
        - Input and command validation and sanitation.
    Implementation:
        - ATM: Validates inputs using regular expressions.
        - Bank: Validates commands and arguments before execution.



Conclusion
Our ATM/Bank system is designed with robust security measures to protect against common threats. By using encryption, message signing, input validation, and rate limiting, we ensure the confidentiality, integrity, and availability of the system. These measures strengthen security while preserving usability for legitimate users.



