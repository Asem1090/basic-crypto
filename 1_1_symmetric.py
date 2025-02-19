from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_key() -> bytes:
    return get_random_bytes(16) # AES key must be either 16, 24, or 32 bytes long

def encrypt_message(key: bytes, message: str) -> tuple[str, bytes]:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher_text).decode(), nonce

def decrypt_message(key: bytes, cipher_text: str, nonce: bytes) -> str:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(base64.b64decode(cipher_text))
    return plain_text.decode()

def main() -> None:
    # Generate a key
    key = generate_key()

    # Encrypt a message
    message = "Secret message"
    encrypted_message, nonce = encrypt_message(key, message)
    print(f"Encrypted: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message(key, encrypted_message, nonce)
    print(f"Decrypted: {decrypted_message}")

if __name__ == "__main__":
    main()