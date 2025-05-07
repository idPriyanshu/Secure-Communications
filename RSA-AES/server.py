import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key

def server():
    private_key, public_key = generate_rsa_keys()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")
    
    conn, addr = server_socket.accept()
    print("Connection established with", addr)
    
    conn.send(public_key)  
    encrypted_aes_key = conn.recv(256)  
    
    
    rsa_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print("Decrypted AES Key:", base64.b64encode(aes_key).decode())
    
    
    message = input("Enter the message to send securely: ")
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())
    encrypted_msg = aes_cipher.nonce + tag + ciphertext
    print("Encrypted Message Sent to Client:", base64.b64encode(encrypted_msg).decode())
    conn.send(encrypted_msg)
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()