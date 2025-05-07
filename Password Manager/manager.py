from cryptography.fernet import Fernet
import base64
import os
import json
import getpass
from hashlib import sha256

KEY_FILE = "key.enc"
PASSWORD_FILE = "passwords.json"

def hash_master_password(master_password):
    return sha256(master_password.encode()).digest()

def generate_encryption_key(master_password):
    key = Fernet.generate_key()
    fernet = Fernet(base64.urlsafe_b64encode(hash_master_password(master_password)))
    encrypted_key = fernet.encrypt(key)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(encrypted_key)
    print("Encryption key generated and secured.")

def get_encryption_key(master_password):
    if not os.path.exists(KEY_FILE):
        print("No key file found. Generate a new one.")
        return None
    with open(KEY_FILE, "rb") as key_file:
        encrypted_key = key_file.read()
    try:
        fernet = Fernet(base64.urlsafe_b64encode(hash_master_password(master_password)))
        return fernet.decrypt(encrypted_key)
    except:
        print("Invalid master password!")
        return None

def save_password(site, password, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_password = fernet.encrypt(password.encode()).decode()
    passwords = load_passwords()
    passwords[site] = encrypted_password
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file, indent=4)
    print("Password saved successfully.")

def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as file:
            return json.load(file)
    return {}

def get_password(site, encryption_key):
    passwords = load_passwords()
    if site in passwords:
        fernet = Fernet(encryption_key)
        return fernet.decrypt(passwords[site].encode()).decode()
    else:
        return "Site not found."

def update_password(site, new_password, encryption_key):
    passwords = load_passwords()
    if site in passwords:
        fernet = Fernet(encryption_key)
        passwords[site] = fernet.encrypt(new_password.encode()).decode()
        with open(PASSWORD_FILE, "w") as file:
            json.dump(passwords, file, indent=4)
        print("Password updated successfully.")
    else:
        print("Site not found.")

def delete_password(site):
    passwords = load_passwords()
    if site in passwords:
        del passwords[site]
        with open(PASSWORD_FILE, "w") as file:
            json.dump(passwords, file, indent=4)
        print("Password deleted successfully.")
    else:
        print("Site not found.")

def main():
    master_password = getpass.getpass("Enter Master Password: ")
    encryption_key = get_encryption_key(master_password)
    if encryption_key is None:
        return
    
    while True:
        print("\nPassword Manager")
        print("1. Save Password")
        print("2. Retrieve Password")
        print("3. Update Password")
        print("4. Delete Password")
        print("5. Exit")
        choice = input("Enter choice: ")
        
        if choice == "1":
            site = input("Enter site name: ")
            password = getpass.getpass("Enter password: ")
            save_password(site, password, encryption_key)
        elif choice == "2":
            site = input("Enter site name: ")
            print("Password:", get_password(site, encryption_key))
        elif choice == "3":
            site = input("Enter site name: ")
            new_password = getpass.getpass("Enter new password: ")
            update_password(site, new_password, encryption_key)
        elif choice == "4":
            site = input("Enter site name: ")
            delete_password(site)
        elif choice == "5":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    if not os.path.exists(KEY_FILE):
        master_password = getpass.getpass("Set up a Master Password: ")
        generate_encryption_key(master_password)
    main()
