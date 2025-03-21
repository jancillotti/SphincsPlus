import hashlib
import ecdsa
import os
import struct
import time
import pyspx.sha2_128s as sphincs_sha256s
import pyspx.sha2_128s as sphincs_sha256f


def ripemd160_sha256(data):
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()

def serialize_transaction(inputs, outputs, address_hex=True):
    tx_version = struct.pack("<L", 1)
    tx_in_count = struct.pack("<B", len(inputs))
    tx_inputs_serialized = b""
    for tx_id, index in inputs:
        tx_id_bytes = bytes.fromhex(tx_id)[::-1]
        tx_index = struct.pack("<L", index)
        script_sig = b""
        script_sig_length = struct.pack("<B", len(script_sig))
        sequence = b"\xff\xff\xff\xff"
        tx_inputs_serialized += tx_id_bytes + tx_index + script_sig_length + script_sig + sequence

    tx_out_count = struct.pack("<B", len(outputs))
    tx_outputs_serialized = b""
    for address, amount in outputs:
        if address_hex:
            address_bytes = bytes.fromhex(address)
        else:
            address_bytes = address
        satoshis = struct.pack("<Q", int(amount * 100_000_000))
        script_pubkey = b"\x76\xa9" + struct.pack("<B", 20) + address_bytes + b"\x88\xac"
        script_pubkey_length = struct.pack("<B", len(script_pubkey))
        tx_outputs_serialized += satoshis + script_pubkey_length + script_pubkey

    tx_locktime = struct.pack("<L", 0)
    return tx_version + tx_in_count + tx_inputs_serialized + tx_out_count + tx_outputs_serialized + tx_locktime

def run_ecdsa():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key.to_string())
    sizes["Public Key"] = len(public_key.to_string())

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key.to_string()).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = private_key.sign(tx_hash)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = public_key.verify(signature, tx_hash)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def run_sphincs_s():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    seed = os.urandom(sphincs_sha256s.crypto_sign_SEEDBYTES)
    timings["Seed Generation"] = time.perf_counter() - start
    sizes["Seed"] = len(seed)

    start = time.perf_counter()
    public_key, private_key = sphincs_sha256s.generate_keypair(seed)
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key)
    sizes["Public Key"] = len(public_key)

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = sphincs_sha256s.sign(tx_hash, private_key)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = sphincs_sha256s.verify(tx_hash, signature, public_key)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def run_sphincs_sha256f():
    timings = {}
    sizes = {}

    start = time.perf_counter()
    seed = os.urandom(sphincs_sha256f.crypto_sign_SEEDBYTES)
    timings["Seed Generation"] = time.perf_counter() - start
    sizes["Seed"] = len(seed)

    start = time.perf_counter()
    public_key, private_key = sphincs_sha256f.generate_keypair(seed)
    timings["Key Pair Generation"] = time.perf_counter() - start
    sizes["Private Key"] = len(private_key)
    sizes["Public Key"] = len(public_key)

    start = time.perf_counter()
    mock_address = ripemd160_sha256(public_key).hex()
    timings["Address Generation"] = time.perf_counter() - start

    start = time.perf_counter()
    prev_tx = hashlib.sha256(b"Previous Fake Transaction").digest().hex()
    tx_inputs = [(prev_tx, 0)]
    tx_outputs = [(mock_address, 0.5)]
    timings["TX Setup"] = time.perf_counter() - start

    start = time.perf_counter()
    raw_tx = serialize_transaction(tx_inputs, tx_outputs)
    timings["TX Serialization"] = time.perf_counter() - start
    sizes["Transaction"] = len(raw_tx)

    start = time.perf_counter()
    tx_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    timings["TX Hashing"] = time.perf_counter() - start

    start = time.perf_counter()
    signature = sphincs_sha256f.sign(tx_hash, private_key)
    timings["Signing"] = time.perf_counter() - start
    sizes["Signature"] = len(signature)

    start = time.perf_counter()
    valid = sphincs_sha256f.verify(tx_hash, signature, public_key)
    timings["Verification"] = time.perf_counter() - start

    return timings, sizes, valid

def print_comparison_table(title, d1, d2, d3, label1="ECDSA", label2="SPHINCS+ SHA256s", label3="SPHINCS+ SHA256f"):
    print(f"\n{title}")
    print("-" * len(title))
    keys = sorted(set(d1) | set(d2) | set(d3))
    print(f"{'Step':<30}{label1:^15}{label2:^20}{label3:^20}")
    print("-" * 85)
    for key in keys:
        v1 = d1.get(key, '')
        v2 = d2.get(key, '')
        v3 = d3.get(key, '')

        def fmt(v):
            if isinstance(v, float):
                return f"{v:.6f}s"
            elif isinstance(v, int):
                return f"{v} B"
            return str(v)

        print(f"{key:<30}{fmt(v1):^15}{fmt(v2):^20}{fmt(v3):^20}")

# Run all 
ecdsa_time, ecdsa_size, ecdsa_valid = run_ecdsa()
sphincs_time, sphincs_size, sphincs_valid = run_sphincs_s()
sphincs256f_time, sphincs256f_size, sphincs256f_valid = run_sphincs_sha256f()

# Print comparisons
print_comparison_table("Timing Comparison", ecdsa_time, sphincs_time, sphincs256f_time)
print_comparison_table("Size Comparison", ecdsa_size, sphincs_size, sphincs256f_size)

print("\nSignature Validity")
print("------------------")
print(f"ECDSA:               {ecdsa_valid}")
print(f"SPHINCS+ SHA256s:       {sphincs_valid}")
print(f"SPHINCS+ SHA256f:    {sphincs256f_valid}")
