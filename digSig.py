from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils


# a. Berechnung eines Public-Key Schlüsselpaars (sk, pk) (Elliptic Curve Cryptography)
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# b. Berechnung eines Hashwertes (SHA-256) für Nachrichten
def calculate_message_hash(message):
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(message.encode())
    return digest.finalize()


# e. Signieren einer Nachricht
def sign_message(private_key, message):
    message_hash = calculate_message_hash(message)
    signature = private_key.sign(
        message_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    return signature


# f. Verifikation einer Signatur
def verify_signature(public_key, message, signature):
    message_hash = calculate_message_hash(message)
    try:
        public_key.verify(
            signature,
            message_hash,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return True
    except Exception:
        return False


# Hauptprogramm
if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    message = input("Geben Sie Ihre Nachricht ein: ")
    signature = sign_message(private_key, message)
    is_signature_valid = verify_signature(public_key, message, signature)

    print(
        f"Public Key: {public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)}")
    print(
        f"Private Key: {private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())}")
    print(f"Message Hash: {calculate_message_hash(message).hex()}")
    print(f"Signature: {signature.hex()}")
    print(f"Is Signature Valid: {is_signature_valid}")
