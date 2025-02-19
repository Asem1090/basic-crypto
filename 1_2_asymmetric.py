from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys() -> tuple[bytes, bytes]:
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(public_key: bytes, message: str) -> str:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    cipher_text = cipher.encrypt(message.encode())
    return base64.b64encode(cipher_text).decode()

def decrypt_message(private_key: bytes, cipher_text: str) -> str:
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plain_text = cipher.decrypt(base64.b64decode(cipher_text))
    return plain_text.decode()

def main() -> None:
    # Generate keys
    private_key, public_key = generate_keys()

    # Encrypt a message
    message = "Secret message"
    encrypted_message = encrypt_message(public_key, message)
    print(f"Encrypted: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted: {decrypted_message}")

if __name__ == "__main__":
    main()