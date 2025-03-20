import hashlib
import ecdsa
import struct

# Generate a new private key (random for demonstration)
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
public_key = private_key.get_verifying_key()


# Mock Bitcoin-like address (hash of the public key)
def ripemd160_sha256(data):
    """Perform SHA-256 followed by RIPEMD-160 (used in Bitcoin addresses)."""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()


# Create a mock Bitcoin address (compressed public key -> hashed)
mock_address = ripemd160_sha256(public_key.to_string()).hex()

# Fake Previous Transaction (UTXO)
previous_tx_id = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
output_index = 0  # Assume this is the first output in the previous transaction

# Mock new transaction inputs and outputs
tx_inputs = [(previous_tx_id, output_index)]  # (tx_id, output index)
tx_outputs = [(mock_address, 0.5)]  # (recipient, BTC amount)


# Serialize the transaction like Bitcoin's raw transaction format
def serialize_transaction(inputs, outputs):
    """Create a Bitcoin-like transaction serialization."""
    tx_version = struct.pack("<L", 1)  # 4-byte little-endian version (1)

    # Number of inputs
    tx_in_count = struct.pack("<B", len(inputs))  # 1-byte input count
    tx_inputs_serialized = b""

    for tx_id, index in inputs:
        tx_id_bytes = bytes.fromhex(tx_id)[::-1]  # Reverse bytes (Bitcoin format)
        tx_index = struct.pack("<L", index)  # 4-byte little-endian index
        script_sig = b""  # Empty scriptSig (mock)
        script_sig_length = struct.pack("<B", len(script_sig))
        sequence = b"\xff\xff\xff\xff"  # Default sequence number
        tx_inputs_serialized += tx_id_bytes + tx_index + script_sig_length + script_sig + sequence

    # Number of outputs
    tx_out_count = struct.pack("<B", len(outputs))  # 1-byte output count
    tx_outputs_serialized = b""

    for address, amount in outputs:
        satoshis = struct.pack("<Q", int(amount * 100_000_000))  # Convert BTC to satoshis (8 bytes)
        script_pubkey = b"\x76\xa9" + struct.pack("<B", 20) + bytes.fromhex(address) + b"\x88\xac"  # P2PKH script
        script_pubkey_length = struct.pack("<B", len(script_pubkey))
        tx_outputs_serialized += satoshis + script_pubkey_length + script_pubkey

    tx_locktime = struct.pack("<L", 0)  # 4-byte locktime (0 for no lock)

    return tx_version + tx_in_count + tx_inputs_serialized + tx_out_count + tx_outputs_serialized + tx_locktime


# Serialize the transaction
raw_tx = serialize_transaction(tx_inputs, tx_outputs)

# Bitcoin-style double SHA-256 hashing
tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()

# Sign the transaction hash using ECDSA
signature = private_key.sign(tx_hash)

# Verify the signature using the public key
is_valid = public_key.verify(signature, tx_hash)

# Display results
print("Mock Bitcoin Transaction")
print("-------------------------")
print("Mock Address (Recipient):", mock_address)
print("Previous TX ID:", previous_tx_id)
print("Serialized Transaction:", raw_tx.hex())
print("Transaction Hash (Double SHA-256):", tx_hash.hex())
print("Signature:", signature.hex())
print("Signature Valid:", is_valid)
