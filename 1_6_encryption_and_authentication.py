from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

def generate_keys() -> tuple[bytes, bytes]:
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(private_key: bytes, message: str) -> str:
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(rsa_key).sign(h)
    return base64.b64encode(signature).decode()

def verify_message(public_key: bytes, signature: str, message: str) -> bool:
    rsa_key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(rsa_key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

def encrypt_message(public_key: bytes, message: str) -> str:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_chunks = []
    for i in range(0, len(message), 190):
        chunk = message[i:i+190]
        encrypted_chunk = cipher.encrypt(chunk.encode())
        encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())
    return ':'.join(encrypted_chunks)

def decrypt_message(private_key: bytes, encrypted_message: str) -> str:
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_chunks = encrypted_message.split(':')
    decrypted_message = ''
    for chunk in encrypted_chunks:
        decrypted_chunk = cipher.decrypt(base64.b64decode(chunk))
        decrypted_message += decrypted_chunk.decode()
    return decrypted_message

def main() -> None:
    # Generate keys
    private_key, public_key = generate_keys()

    # Sign a message
    message = "Secret message"
    signed_message = sign_message(private_key, message)
    print(f"Signed: {signed_message}\n")

    # Join the signature with the plaintext message
    combined_message = f"{signed_message}:{message}"

    # Encrypt the combined message
    encrypted_message = encrypt_message(public_key, combined_message)
    print(f"Encrypted: {encrypted_message}\n")

    # Decrypt the combined message
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted: {decrypted_message}\n")

    # Split the decrypted message to get the signature and the original message
    decrypted_signature, original_message = decrypted_message.split(":", 1)

    # Verify the message
    if verify_message(public_key, decrypted_signature, original_message):
        print(f"Verified: {original_message}")
    else:
        print("Verification failed")

if __name__ == "__main__":
    main()
