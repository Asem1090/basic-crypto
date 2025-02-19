from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hmac
import hashlib

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

def sign_message(mac_key: bytes, message: str) -> str:
    mac = hmac.new(mac_key, message.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()

def verify_signature(mac_key: bytes, message: str, signature: str) -> bool:
    mac = hmac.new(mac_key, message.encode(), hashlib.sha256)
    expected_signature = base64.b64encode(mac.digest()).decode()
    return hmac.compare_digest(expected_signature, signature)

def sender(encryption_key: bytes, mac_key: bytes, message: str) -> tuple[str, bytes, str]:
    encrypted_message, nonce = encrypt_message(encryption_key, message)
    signature = sign_message(mac_key, encrypted_message)
    return encrypted_message, nonce, signature

def receiver(encryption_key: bytes, mac_key: bytes, encrypted_message: str, nonce: bytes, signature: str) -> str:
    if verify_signature(mac_key, encrypted_message, signature):
        print("Signature is valid.")
        decrypted_message = decrypt_message(encryption_key, encrypted_message, nonce)
        return decrypted_message
    else:
        print("Signature is invalid.")
        return ""

def main() -> None:
    # Generate keys
    encryption_key = generate_key()
    mac_key = generate_key()

    # Sender encrypts and signs the message
    print("Sender:")
    message = "Secret message"
    print(f"Message: {message}")
    encrypted_message, nonce, signature = sender(encryption_key, mac_key, message)
    print(f"Encrypted: {encrypted_message}")
    print(f"Signature: {signature}")

    # Receiver verifies the signature and decrypts the message
    print("\nReceiver:")
    decrypted_message = receiver(encryption_key, mac_key, encrypted_message, nonce, signature)
    print(f"Decrypted: {decrypted_message}")

if __name__ == "__main__":
    main()
