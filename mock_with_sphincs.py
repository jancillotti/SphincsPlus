# Re-import required modules
import hashlib
import json
import time
import os
import random
import pandas as pd
import pyspx.sha2_128s as sphincs

seed = os.urandom(sphincs.crypto_sign_SEEDBYTES)

# Define SPHINCS+ for real cryptographic signing
class SPHINCSPlus:
    """ SPHINCS+ Digital Signature Handling """

    @staticmethod
    def generate_keypair():
        """ Generate a real SPHINCS+ keypair """
        if sphincs is None:
            raise ImportError("pyspx is not installed. Install it using `pip install pyspx`.")
        public_key, private_key = sphincs.generate_keypair(seed)
        return public_key, private_key

    @staticmethod
    def sign(message, private_key):
        """ Signs a message using SPHINCS+ """
        if sphincs is None:
            raise ImportError("pyspx is not installed. Install it using `pip install pyspx`.")
        return sphincs.sign(message, private_key)

    @staticmethod
    def verify(message, signature, public_key):
        """ Verifies a SPHINCS+ signature """
        if sphincs is None:
            raise ImportError("pyspx is not installed. Install it using `pip install pyspx`.")
        return sphincs.verify(message, signature, public_key)


# Define UTXO Set for managing balances
class UTXOSet:
    """ Tracks unspent transaction outputs (UTXOs) """

    def __init__(self):
        self.utxos = {}  # Dictionary of {tx_id: {recipient_pubkey: amount}}

    def add_transaction(self, tx_id, recipient_pubkey, amount):
        """ Adds a UTXO for a recipient """
        if tx_id not in self.utxos:
            self.utxos[tx_id] = {}
        self.utxos[tx_id][recipient_pubkey] = amount

    def spend_transaction(self, tx_id, sender_pubkey):
        """ Spends a UTXO, removing it from the set """
        if tx_id in self.utxos and sender_pubkey in self.utxos[tx_id]:
            del self.utxos[tx_id][sender_pubkey]
            if not self.utxos[tx_id]:  # If no recipients left, remove tx
                del self.utxos[tx_id]
            return True
        return False

    def check_balance(self, sender_pubkey):
        """ Returns the total balance of a public key """
        balance = 0
        for tx in self.utxos.values():
            if sender_pubkey in tx:
                balance += tx[sender_pubkey]
        return balance


# Define Proof-of-Work Block
class PoWBlock:
    """ Block with Proof-of-Work mining """

    def __init__(self, index, previous_hash, transactions, difficulty=2):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = self.mine_block()

    def compute_hash(self):
        """ Computes the hash of the block """
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self):
        """ Implements Proof-of-Work: Finds a valid hash below the difficulty target """
        prefix = "0" * self.difficulty  # Difficulty target (e.g., "00" for difficulty 2)
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(prefix):
                return self.hash
            self.nonce += 1


# Define Proof-of-Work Blockchain with UTXO tracking
class PoWBlockchain:
    """ Blockchain with PoW and UTXO tracking """

    def __init__(self, difficulty=2):
        self.chain = []
        self.utxos = UTXOSet()
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = PoWBlock(0, "0", [], self.difficulty)
        self.chain.append(genesis_block)

    def add_block(self, transactions):
        """ Adds a new block after validating transactions """
        valid_transactions = []

        for tx in transactions:
            if self.validate_transaction(tx):
                valid_transactions.append(tx)
                # Spend sender's UTXO and create a new one for recipient
                tx_id = hashlib.sha256(json.dumps(tx.to_dict(), sort_keys=True).encode()).hexdigest()
                self.utxos.spend_transaction(tx_id, tx.sender_pubkey)
                self.utxos.add_transaction(tx_id, tx.recipient_pubkey, tx.amount)

        previous_hash = self.chain[-1].hash
        new_block = PoWBlock(len(self.chain), previous_hash, valid_transactions, self.difficulty)
        self.chain.append(new_block)

    def validate_transaction(self, transaction):
        """ Ensures transaction is valid before adding to block """
        sender_balance = self.utxos.check_balance(transaction.sender_pubkey)
        if sender_balance >= transaction.amount and transaction.verify():
            return True
        return False


# Define Transaction Class with SPHINCS+ Digital Signatures
class Transaction:
    def __init__(self, sender_pubkey, sender_privkey, recipient_pubkey, amount, signature=None):
        self.sender_pubkey = sender_pubkey
        self.sender_privkey = sender_privkey  # Store private key for correct verification
        self.recipient_pubkey = recipient_pubkey
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            "sender_pubkey": self.sender_pubkey.hex(),
            "recipient_pubkey": self.recipient_pubkey.hex(),
            "amount": self.amount
        }

    def sign(self):
        message = json.dumps(self.to_dict(), sort_keys=True).encode()
        self.signature = SPHINCSPlus.sign(message, self.sender_privkey)

    def verify(self):
        if not self.signature:
            return False
        message = json.dumps(self.to_dict(), sort_keys=True).encode()
        return SPHINCSPlus.verify(message, self.signature, self.sender_pubkey)


# Initialize blockchain with mining and UTXO tracking
pow_blockchain = PoWBlockchain(difficulty=3)

# Generate SPHINCS+ keys for users
users = {f"User_{i}": SPHINCSPlus.generate_keypair() for i in range(3)}

# Create transactions between users
tx1 = Transaction(users["User_0"][0], users["User_0"][1], users["User_1"][0], random.randint(1, 100))
tx1.sign()

tx2 = Transaction(users["User_1"][0], users["User_1"][1], users["User_2"][0], random.randint(1, 100))
tx2.sign()

tx3 = Transaction(users["User_2"][0], users["User_2"][1], users["User_0"][0], random.randint(1, 100))
tx3.sign()

# Add block with mined transactions
pow_blockchain.add_block([tx1, tx2, tx3])

# Display blockchain with mining
df = pd.DataFrame([{
    "Index": block.index,
    "Timestamp": block.timestamp,
    "Hash": block.hash,
    "Prev Hash": block.previous_hash,
    "Transactions": [t.to_dict() for t in block.transactions],
    "Nonce": block.nonce
} for block in pow_blockchain.chain])

print(df)