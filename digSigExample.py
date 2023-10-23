from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils


# a. Berechnung eines Public-Key Schlüsselpaars (Elliptic Curve Cryptography)
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


# Hauptprogramm Aufgabe 4
#a. Signieren Sie folgende Transaktion „Alice pays Bob $20“.
#b. Verifizieren Sie anschließend die Signatur und den Inhalt.
#c. Signieren Sie die Transaktion „Bob pays Alice $20“.
#d. Verifizieren Sie die Signatur und den Inhalt.

if __name__ == "__main__":
    # a. Signieren der Transaktion "Alice pays Bob $20"
    private_key_alice, public_key_alice = generate_key_pair()
    message_alice_to_bob = "Alice pays Bob $20"
    signature_alice_to_bob = sign_message(private_key_alice, message_alice_to_bob)

    # b. Verifizieren der Signatur und des Inhalts
    is_signature_valid_alice_to_bob = verify_signature(public_key_alice, message_alice_to_bob, signature_alice_to_bob)

    print(f"Transaction: {message_alice_to_bob}")
    print(f"Signature: {signature_alice_to_bob.hex()}")
    print(f"Is Signature Valid: {is_signature_valid_alice_to_bob}")

    # c. Signieren der Transaktion "Bob pays Alice $20"
    private_key_bob, public_key_bob = generate_key_pair()
    message_bob_to_alice = "Bob pays Alice $20"
    signature_bob_to_alice = sign_message(private_key_bob, message_bob_to_alice)

    # d. Verifizieren der Signatur und des Inhalts
    is_signature_valid_bob_to_alice = verify_signature(public_key_bob, message_bob_to_alice, signature_bob_to_alice)

    print(f"Transaction: {message_bob_to_alice}")
    print(f"Signature: {signature_bob_to_alice.hex()}")
    print(f"Is Signature Valid: {is_signature_valid_bob_to_alice}")
