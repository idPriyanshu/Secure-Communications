
import hmac
import hashlib
import socket

SECRET_KEY = input("Enter the shared secret key: ").encode()

def generate_hmac(message: str, key: bytes) -> str:
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message: str, received_hmac: str, key: bytes) -> bool:
    computed_hmac = generate_hmac(message, key)
    return hmac.compare_digest(computed_hmac, received_hmac)

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Waiting for connection...")
    
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    
    conn.sendall(SECRET_KEY)
    client_key = conn.recv(1024)
    
    if client_key != SECRET_KEY:
        print("Shared secret keys do not match! Closing connection.")
        conn.close()
        server_socket.close()
        return
    
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        
        message, received_hmac = data.split(":::")
        if verify_hmac(message, received_hmac, SECRET_KEY):
            print(f"Received authentic message: {message}")
            
            response = input("Enter response: ")
            response_hmac = generate_hmac(response, SECRET_KEY)
            conn.sendall(f"{response}:::{response_hmac}".encode())
        else:
            print("Message verification failed!")
            conn.sendall("ERROR:::Message verification failed".encode())
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()
