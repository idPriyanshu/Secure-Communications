import socket
import pickle
import time
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_dsa_keys():
    key = DSA.generate(1024)
    return key, key.publickey()

def sign_message(message, private_key):
    hash_obj = SHA256.new(message.encode())
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

def verify_signature(message, signature, public_key):
    hash_obj = SHA256.new(message.encode())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    alice_private_key, alice_public_key = generate_dsa_keys()
    alice_public_key_bytes = alice_public_key.export_key()  

    print("Alice's Public Key:\n", alice_public_key_bytes)

    time.sleep(1)  # Small delay to ensure server is ready

    bob_public_key_bytes = client_socket.recv(4096)
    if not bob_public_key_bytes:
        print("No data received from Bob. Closing connection.")
        client_socket.close()
        return

    bob_public_key = DSA.import_key(pickle.loads(bob_public_key_bytes)) 
   

    client_socket.send(pickle.dumps(alice_public_key_bytes))  

    message = input("Enter message to Bob: ")
    signature = sign_message(message, alice_private_key)
    client_socket.send(pickle.dumps({'message': message, 'signature': signature}))

    response_data = client_socket.recv(4096)
    if not response_data:
        print("No response from Bob. Connection might be closed.")
        client_socket.close()
        return

    response_message_data = pickle.loads(response_data)
    response_message, response_signature = response_message_data['message'], response_message_data['signature']

    if verify_signature(response_message, response_signature, bob_public_key):
        print(f"Bob says: {response_message} (Signature Verified)")
    else:
        print("Invalid signature from Bob!")

    client_socket.close()

if __name__ == "__main__":
    client()
