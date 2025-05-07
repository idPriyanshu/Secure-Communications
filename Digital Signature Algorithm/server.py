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

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Bob (Server) is waiting for a connection...")

    bob_private_key, bob_public_key = generate_dsa_keys()
    bob_public_key_bytes = bob_public_key.export_key()  

   
    conn, addr = server_socket.accept()
    print("Connection established with", addr)

    time.sleep(1)  
    conn.send(pickle.dumps(bob_public_key_bytes))  

    alice_public_key_bytes = conn.recv(4096)
    if not alice_public_key_bytes:
        print("No data received from Alice. Closing connection.")
        conn.close()
        return

    alice_public_key = DSA.import_key(pickle.loads(alice_public_key_bytes))  
    print("Received Alice's Public Key:\n", alice_public_key.export_key())

    while True:
        data = conn.recv(4096)
        if not data:
            print("Connection closed by Alice.")
            break

        message_data = pickle.loads(data)
        message, signature = message_data['message'], message_data['signature']

        if verify_signature(message, signature, alice_public_key):
            print(f"Alice says: {message} (Signature Verified)")
            response = input("Enter response to Alice: ")
            response_signature = sign_message(response, bob_private_key)
            conn.send(pickle.dumps({'message': response, 'signature': response_signature}))
        else:
            print("Invalid signature from Alice!")

    conn.close()

if __name__ == "__main__":
    server()
