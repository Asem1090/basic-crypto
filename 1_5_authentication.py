from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
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

def main() -> None:
    # Generate keys
    private_key, public_key = generate_keys()

    # Sign a message
    message = "Secret message"
    signed_message = sign_message(private_key, message)
    print(f"Signed: {signed_message}")

    # Verify the message
    if (verify_message(public_key, signed_message, message)):
        print(f"Verified: {message}")
    else:
        print("Verification failed")

if __name__ == "__main__":
    main()
