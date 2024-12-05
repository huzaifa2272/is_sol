import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import json
import os

# AES Encryption/Decryption functions
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Generate salt
def generate_salt():
    return get_random_bytes(16)

# Hash password using SHA-256 with salt
def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

# Store credentials (username, email, hashed password, and salt)
def store_credentials(email, username, hashed_password, salt):
    with open("creds.txt", "a") as file:
        file.write(f"{email},{username},{hashed_password},{salt.hex()}\n")

# Check if username exists
def username_exists(username):
    if not os.path.exists("creds.txt"):
        return False
    with open("creds.txt", "r") as file:
        for line in file:
            stored_username = line.split(',')[1]
            if stored_username == username:
                return True
    return False

# Retrieve credentials (hashed_password, salt) for a given username
def retrieve_credentials(username):
    if not os.path.exists("creds.txt"):
        return None, None
    with open("creds.txt", "r") as file:
        for line in file:
            email, stored_username, hashed_password, salt = line.strip().split(',')
            if stored_username == username:
                return hashed_password, bytes.fromhex(salt)
    return None, None

# Perform Diffie-Hellman Key Exchange
def diffie_hellman_key_exchange(client_socket):
    P = 23  # Public prime number (shared between server and client)
    G = 5   # Public primitive root (shared)

    # Server generates private key
    b = get_random_bytes(16)
    B = pow(G, int.from_bytes(b, byteorder='big'), P)

    # Receive client's public key
    A = int(client_socket.recv(1024).decode())

    # Send server's public key
    client_socket.send(str(B).encode())

    # Calculate shared key
    shared_key = pow(A, int.from_bytes(b, byteorder='big'), P)

    # Derive AES key from the shared key
    return hashlib.sha256(str(shared_key).encode()).digest()

# Handle client interactions
def handle_client(client_socket):
    while True:
        try:
            # Receive action request (register, login, chat) from the client
            action = client_socket.recv(1024).decode()
            if not action:
                break

            print(f"Action received: {action}")

            # Perform Diffie-Hellman for each workflow
            shared_key = diffie_hellman_key_exchange(client_socket)

            if action == 'register':
                # Registration logic
                handle_registration(client_socket, shared_key)
            elif action == 'login':
                # Login logic
                handle_login(client_socket, shared_key)
            elif action == 'chat':
                # Chat logic
                handle_chat(client_socket, shared_key)
            else:
                print("Unknown action received.")
        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()

# Registration logic
def handle_registration(client_socket, shared_key):
    # Receive and decrypt registration data
    encrypted_data = client_socket.recv(1024)
    decrypted_data = aes_decrypt(shared_key, encrypted_data)
    message = json.loads(decrypted_data)

    email = message['email']
    username = message['username']
    password = message['password']

    if username_exists(username):
        response = "Username already exists."
    else:
        # Hash the password with salt
        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        # Store credentials
        store_credentials(email, username, hashed_password, salt)
        response = "Registration successful."

    # Encrypt and send response
    encrypted_response = aes_encrypt(shared_key, response)
    client_socket.send(encrypted_response)

# Login logic
def handle_login(client_socket, shared_key):
    # Receive and decrypt login data
    encrypted_data = client_socket.recv(1024)
    decrypted_data = aes_decrypt(shared_key, encrypted_data)
    message = json.loads(decrypted_data)

    username = message['username']
    password = message['password']

    # Retrieve stored credentials
    stored_hashed_password, salt = retrieve_credentials(username)

    if stored_hashed_password is None:
        response = "Username not found."
    else:
        hashed_password = hash_password(password, salt)
        if hashed_password == stored_hashed_password:
            response = "Login successful. You can now start chatting."
        else:
            response = "Invalid password."

    # Encrypt and send response
    encrypted_response = aes_encrypt(shared_key, response)
    client_socket.send(encrypted_response)

# Chat logic
def handle_chat(client_socket, shared_key):
    while True:
        # Receive and decrypt chat message
        encrypted_data = client_socket.recv(1024)
        decrypted_message = aes_decrypt(shared_key, encrypted_data)
        decrypted_message = json.loads(decrypted_message)


        print(f"Client: {decrypted_message['message']}")
        if decrypted_message['message'] == 'bye':
            print("Client ended the chat.")
            break

        # Send a response back to the client
        response = input("You (Server): ")

        # Encrypt and send response
        encrypted_response = aes_encrypt(shared_key, response)
        client_socket.send(encrypted_response)

# Main server function
def main():
    print("\n\t>>>>>>>>>> Secure Chat Server <<<<<<<<<<\n\n")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', 8080)
    server_socket.bind(server_address)
    server_socket.listen(5)

    while True:
        # Accept incoming connection
        client_socket, _ = server_socket.accept()

        # Handle client in a separate process/thread
        handle_client(client_socket)

if __name__ == "__main__":
    main()
