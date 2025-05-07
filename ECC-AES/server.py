import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import binascii

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 12345))
server.listen(1)

print("Waiting for connection...")
conn, addr = server.accept()
print(f"Connected to {addr}")

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962, 
    format=serialization.PublicFormat.UncompressedPoint
)

print(f"Server Private Key: {private_key.private_numbers().private_value}")
print(f"Server Public Key: {binascii.hexlify(public_bytes).decode()}")

conn.send(public_bytes)
client_public_bytes = conn.recv(1024)

client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)
shared_secret = private_key.exchange(ec.ECDH(), client_public_key)

print(f"Client Public Key: {binascii.hexlify(client_public_bytes).decode()}")
print(f"Server Shared Secret: {binascii.hexlify(shared_secret).decode()}")

aes_key = hashlib.sha256(shared_secret).digest()
print(f"Derived AES Key: {binascii.hexlify(aes_key).decode()}")

iv = os.urandom(16)
conn.send(iv)
print(f"IV Sent: {binascii.hexlify(iv).decode()}")

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()

message = input("Enter message to send: ").ljust(16).encode()
encrypted_message = encryptor.update(message) + encryptor.finalize()
conn.send(encrypted_message)

print(f"Encrypted Message Sent: {binascii.hexlify(encrypted_message).decode()}")

conn.close()
server.close()
