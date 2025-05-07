# 🔐 Secure Communication and Cryptography Suite

This repository contains implementations of various cryptographic protocols and tools built in Python. These are designed to demonstrate secure communication between client and server, digital signatures, secure password storage, and message authentication.

## 📁 Project Structure

- `ECC`  
  Secure client-server communication using **Elliptic Curve Diffie-Hellman (ECDH)** for key exchange and communication

- `RSA-AES/`  
  Hybrid encryption system using **RSA** for secure key exchange and **AES** for encrypting messages.

- `Digital Signature Algorithm/`  
  Demonstrates message signing and verification using **Elliptic Curve Digital Signature Algorithm (ECDSA)** to ensure integrity and authenticity.

- `HMAC/`  
  Implements **Hash-Based Message Authentication Code** using SHA-256 to validate message integrity and authenticity.

- `Password Manager/`  
  A minimal **local password manager** that stores credentials securely using encryption and hashing.



## 🚀 How to Run

Each folder contains its own client and server (or main) scripts. To run a sample:

1. Navigate to a specific folder:
   ```bash
   cd {directory}
3. Run the server script:
   ```bash
   python server.py
4. In a new terminal, run the client script:
   ```bash
   python client.py

