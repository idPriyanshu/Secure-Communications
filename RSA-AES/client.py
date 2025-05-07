import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    
    public_key = client_socket.recv(450)  
    rsa_public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    
    aes_key = get_random_bytes(32)  
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)  
    
    print("Encrypted AES Key Sent.")
    
    
    encrypted_message = client_socket.recv(1024)
    print("Encrypted Message Received from Server:", base64.b64encode(encrypted_message).decode())
    nonce, tag, ciphertext = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
    
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = aes_cipher.decrypt_and_verify(ciphertext, tag).decode()
    print("Decrypted Message from Server:", decrypted_message)
    
    client_socket.close()

if __name__ == "__main__":
    client()