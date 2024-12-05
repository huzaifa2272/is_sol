import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import json

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

# Perform Diffie-Hellman Key Exchange
def diffie_hellman_key_exchange(sock):
    P = 23  # Public prime number (shared between server and client)
    G = 5   # Public primitive root (shared)

    # Client generates private key
    a = get_random_bytes(16)
    A = pow(G, int.from_bytes(a, byteorder='big'), P)

    # Send public key to server
    sock.send(str(A).encode())

    # Receive server's public key
    B = int(sock.recv(1024).decode())

    # Calculate shared key
    shared_key = pow(B, int.from_bytes(a, byteorder='big'), P)

    # Derive AES key from the shared key
    return hashlib.sha256(str(shared_key).encode()).digest()

# Create socket and connect to server
def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)
    sock.connect(server_address)
    return sock

# Registration workflow with a new Diffie-Hellman key exchange
def register(sock):
    # Send action type to the server
    sock.send("register".encode())

    print("Starting Diffie-Hellman key exchange for registration...")
    shared_key = diffie_hellman_key_exchange(sock)

    email = input("Enter Email: ")
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # Prepare registration data
    registration_data = json.dumps({
        'email': email,
        'username': username,
        'password': password
    })

    # Encrypt and send registration data
    encrypted_data = aes_encrypt(shared_key, registration_data)
    sock.send(encrypted_data)

    # Receive and decrypt server's response
    response = sock.recv(1024)
    decrypted_response = aes_decrypt(shared_key, response)
    print(decrypted_response)

# Login workflow with a new Diffie-Hellman key exchange
def login(sock):
    # Send action type to the server
    sock.send("login".encode())

    print("Starting Diffie-Hellman key exchange for login...")
    shared_key = diffie_hellman_key_exchange(sock)

    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # Prepare login data
    login_data = json.dumps({
        'username': username,
        'password': password
    })

    # Encrypt and send login data
    encrypted_data = aes_encrypt(shared_key, login_data)
    sock.send(encrypted_data)

    # Receive and decrypt login response
    response = sock.recv(1024)
    decrypted_response = aes_decrypt(shared_key, response)
    print(decrypted_response)

    # If login is successful, start chat
    if "Login successful" in decrypted_response:
        chat(sock)

# Chat workflow with a new Diffie-Hellman key exchange
def chat(sock):
    # Send action type to the server
    sock.send("chat".encode())

    print("Starting Diffie-Hellman key exchange for chat...")
    shared_key = diffie_hellman_key_exchange(sock)

    print("\nYou are now in the chat. Type 'bye' to end the chat.\n")

    while True:
        message = input("You: ")
        # Prepare chat message
        chat_message = json.dumps({
            'message': message
        })

        # Encrypt and send the chat message
        encrypted_message = aes_encrypt(shared_key, chat_message)
        sock.send(encrypted_message)
        if message.lower()=="bye":
            break
        # Receive and decrypt the server's response
        response = sock.recv(1024)
        decrypted_response = aes_decrypt(shared_key, response)
        print(f"Server: {decrypted_response}")
        if(decrypted_response == "bye"):
            print("Server has ended the chat.")
            break

# Main program loop
def main():
    print("\n\t>>>>>>>>>> Secure Chat Client <<<<<<<<<<\n\n")

    sock = create_socket()
    print("Changes Made")
    while True:
        print("\nOptions:\n1. Register\n2. Login\n3. Exit")
        option = input("Enter your choice: ")

        if option == "1":
            register(sock)
        elif option == "2":
            login(sock)
        elif option == "3":
            print("Exiting...")
            break
        else:
            print("Invalid option, please try again.")

    sock.close()

if __name__ == "__main__":
    main()
