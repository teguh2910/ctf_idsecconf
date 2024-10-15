# ctf_idsecconf

import hashlib
import bcrypt
from pwn import *
import blake3

# Define the server and port
server = '103.76.120.56'
port = 1337

# Connect to the server
r = remote(server, port, level='debug')

def encode(t, data):
    """Encodes the data using the specified hash type."""
    if t == 'md5':
        return hashlib.md5(data.encode()).hexdigest()
    elif t == 'sha256':
        return hashlib.sha256(data.encode()).hexdigest()
    elif t == 'sha512':
        return hashlib.sha512(data.encode()).hexdigest()
    elif t == 'bcrypt (round 4)':
        return bcrypt.hashpw(data.encode(), bcrypt.gensalt(4)).decode()
    elif t == 'blake3':
        return blake3.blake3(data.encode()).hexdigest()
    else:
        return None  # Return None for unsupported types

while True:
    # Receive the challenge
    challenge = r.recvuntil('\n').decode()
    print(challenge)

    # Extract the type of hash and the data
    # Example challenge: "Hash dengan algoritma 'sha256' untuk data 'mydata'"
    parts = challenge.split("'")  # Split by quotes to get the hashing algorithm
    parts1 = challenge.split("algoritma") # Split by quotes to get the hashing algorithm
    if len(parts) < 3:
        print("Invalid challenge format.")
        continue

    data = parts[1]  # Hashing algorithm
    t = parts1[1].strip()  # Data to hash

    # Decode the hash
    result = encode(t, data)
    
    if result is None:
        print(f"Unsupported hash type: {t}")
        continue

    # Send the result
    r.sendline(result)
    
    # Receive the response
    response = r.recvuntil('\n').decode()
    print(response)
