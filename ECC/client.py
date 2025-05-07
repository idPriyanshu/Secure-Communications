import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import binascii

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 12345))

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962, 
    format=serialization.PublicFormat.UncompressedPoint
)

print(f"Client Private Key: {private_key.private_numbers().private_value}")
print(f"Client Public Key: {binascii.hexlify(public_bytes).decode()}")

server_public_bytes = client.recv(1024)
client.send(public_bytes)

server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)
shared_secret = private_key.exchange(ec.ECDH(), server_public_key)

print(f"Server Public Key: {binascii.hexlify(server_public_bytes).decode()}")
print(f"Client Shared Secret: {binascii.hexlify(shared_secret).decode()}")

aes_key = hashlib.sha256(shared_secret).digest()
print(f"Derived AES Key: {binascii.hexlify(aes_key).decode()}")

iv = client.recv(16)
print(f"IV Received: {binascii.hexlify(iv).decode()}")

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
decryptor = cipher.decryptor()

encrypted_message = client.recv(1024)
print(f"Encrypted Message Received: {binascii.hexlify(encrypted_message).decode()}")

decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
print(f"Decrypted Message: {decrypted_message.decode().strip()}")

client.close()
