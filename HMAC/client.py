
import hmac
import hashlib
import socket

SECRET_KEY = input("Enter the shared secret key: ").encode()

def generate_hmac(message: str, key: bytes) -> str:
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message: str, received_hmac: str, key: bytes) -> bool:
    computed_hmac = generate_hmac(message, key)
    return hmac.compare_digest(computed_hmac, received_hmac)

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))
    
    server_key = client_socket.recv(1024)
    client_socket.sendall(SECRET_KEY)
    
    if server_key != SECRET_KEY:
        print("Shared secret keys do not match! Closing connection.")
        client_socket.close()
        return
    
    while True:
        message = input("Enter message: ")
        message_hmac = generate_hmac(message, SECRET_KEY)
        client_socket.sendall(f"{message}:::{message_hmac}".encode())
        
        response = client_socket.recv(1024).decode()
        if not response:
            break
        
        response_message, response_hmac = response.split(":::")
        if verify_hmac(response_message, response_hmac, SECRET_KEY):
            print(f"Received authentic response: {response_message}")
        else:
            print("Response verification failed!")
    
    client_socket.close()

if __name__ == "__main__":
    client()
