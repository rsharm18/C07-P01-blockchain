import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from Account import Account
from Block import Block


class Blockchain:
    # Basic blockchain init
    # Includes the chain as a list of blocks in order, pending transactions, and known accounts
    # Includes the current value of the hash target. It can be changed at any point to vary the difficulty
    # Also initiates a genesis block
    def __init__(self, hash_target):
        self._chain = []
        self._pending_transactions = []
        self._invalid_transactions = []
        self._chain.append(self.__create_genesis_block())
        self._hash_target = hash_target
        self._accounts = {}

    def __str__(self):
        return f"Chain:\n{self._chain}\n\nPending Transactions: {self._pending_transactions}\n"

    @property
    def hash_target(self):
        return self._hash_target

    @hash_target.setter
    def hash_target(self, hash_target):
        self._hash_target = hash_target

    # Creating the genesis block, taking arbitrary previous block hash since there is no previous block
    # Using the famous bitcoin genesis block string here :)  
    def __create_genesis_block(self):
        genesis_block = Block(0, [], 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks', None,
                              'Genesis block using same string as bitcoin!')
        return genesis_block

    def __validate_transaction(self, transaction):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(transaction['message'], sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')

        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        # Signature - Encode to bytes and then Base64 Decode to get the original signature format back 
        signature = base64.b64decode(transaction['signature'].encode('utf-8'))

        try:
            # Load the public_key object and verify the signature against the calculated hash
            sender_public_pem = self._accounts.get(transaction['message']['sender']).public_key
            sender_public_key = serialization.load_pem_public_key(sender_public_pem)
            sender_public_key.verify(signature, encoded_message_hash,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
        except InvalidSignature:
            # traceback.print_exc()
            return False

        # print("Transaction is valid!")
        return True

    def __process_transactions(self, transactions):
        # Appropriately transfer value from the sender to the receiver
        # For all transactions, first check that the sender has enough balance. 
        # Return False otherwise

        self.__validate_pending_transactions(transactions=transactions)

        if len(self._invalid_transactions) > 0:
            print(
                "Pending transaction has invalid transactions as it results in negative balance for {}. Need to ignore it".format(
                    [tr['message']['sender'] for tr in self._invalid_transactions]))
            return False

        for transaction in transactions:
            sender: Account = self._accounts.get(transaction['message']['sender'])
            receiver: Account = self._accounts.get(transaction['message']['receiver'])
            value = transaction['message']['value']
            sender.decrease_balance(value)
            receiver.increase_balance(value)

        return True

    # Creates a new block and appends to the chain
    # Also clears the pending transactions as they are part of the new block now
    def create_new_block(self):

        new_block = Block(len(self._chain), self._pending_transactions, self._chain[-1].block_hash, self._hash_target)
        self._invalid_transactions = []
        if self.__process_transactions(self._pending_transactions):
            self._chain.append(new_block)
            self._pending_transactions = []
            return new_block
        else:
            # remove invalid pending transaction
            self._pending_transactions = [tr for tr in self._pending_transactions if
                                          tr not in self._invalid_transactions]

            self.create_new_block()
        return new_block

    # Simple transaction with just one sender, one receiver, and one value
    # Created by the account and sent to the blockchain instance
    def add_transaction(self, transaction):
        # print(" transaction {}".format(transaction))
        if self.__validate_transaction(transaction):
            self._pending_transactions.append(transaction)
            return True
        else:
            print(f'ERROR: Transaction: {transaction} failed signature validation')
            return False

    def __validate_chain_hash_integrity(self):
        # Run through the whole blockchain and ensure that previous hash is actually the hash of the previous block
        # Return False otherwise
        count = 0
        prev_block_hash = None
        valid_chain = True
        for block in self._chain:
            stored_prev_block_hash = block.previous_block_hash

            if count == 0:  # genesis block
                prev_block_hash = block.block_hash
            elif prev_block_hash != stored_prev_block_hash:
                valid_chain = False
                break

            prev_block_hash = block.block_hash
            count += 1

        print("\n __validate_chain_hash_integrity ? {}".format(valid_chain))
        return valid_chain

    def __validate_block_hash_target(self):
        # Run through the whole blockchain and ensure that block hash meets hash target criteria, and is the actual hash of the block
        # Return False otherwise

        count = 0
        valid_chain = True
        for block in self._chain:
            if count == 0:  # genesis block
                count += 1
                continue

            block_hash = self.__generate_block_hash(block)
            if not (self.hash_target > block.block_hash == block_hash):
                valid_chain = False
                break

            count += 1

        print(" __validate_block_hash_target ? {}".format(valid_chain))
        return valid_chain

    # Serializing and utf-8 encoding relevant data, and then hashing and creating a hex representation
    def __generate_block_hash(self, block: Block):
        hash_string = '-'.join(
            [str(block.index), str(block.timestamp), str(block.previous_block_hash), str(block.metadata),
             str(block.hash_target), str(block.nonce), json.dumps(block.transactions, sort_keys=True)])
        encoded_hash_string = hash_string.encode('utf-8')
        block_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        return block_hash

    def __validate_complete_account_balances(self):
        # Run through the whole blockchain and ensure that balances never become negative from any transaction
        # Return False otherwise

        count = 0

        account_balance_map: dict = {}
        valid_block = True
        for block in self._chain:
            if count == 0:  # genesis block
                count += 1
                continue
            self._invalid_transactions = []
            account_balance_map = self.__validate_pending_transactions(transactions=block.transactions,
                                                                       account_balance_map=account_balance_map,
                                                                       use_initial_balance=True)

            if len(self._invalid_transactions) > 0:
                print(
                    " __validate_complete_account_balances ==> Pending transaction has invalid transactions as it results in negative balance for {}. Need to ignore it".format(
                        [tr['message']['sender'] for tr in self._invalid_transactions]))
                valid_block = False
                break

        print(" __validate_complete_account_balances ? {} \n".format(valid_block))
        return valid_block

    # Blockchain validation function
    # Runs through the whole blockchain and applies appropriate validations
    def validate_blockchain(self):
        # Call __validate_chain_hash_integrity and implement that method. Return False if check fails
        # Call __validate_block_hash_target and implement that method. Return False if check fails
        # Call __validate_complete_account_balances and implement that method. Return False if check fails

        valid_blockchain = False
        if self.__validate_chain_hash_integrity():
            if self.__validate_block_hash_target():
                if self.__validate_complete_account_balances():
                    valid_blockchain = True

        return valid_blockchain

    def add_account(self, account):
        self._accounts[account.id] = account

    def get_account_balances(self):
        return [{'id': account.id, 'balance': account.balance} for account in self._accounts.values()]

    def __validate_pending_transactions(self, transactions=None, account_balance_map=None, use_initial_balance=False):

        if account_balance_map is None:
            account_balance_map = {}

        if transactions is None:
            transactions = []

        for tr in transactions:
            sender: Account = self._accounts.get(tr['message']['sender'])
            receiver: Account = self._accounts.get(tr['message']['receiver'])
            value = tr['message']['value']

            sender_balance = sender.initial_balance if use_initial_balance else sender.balance
            receiver_balance = receiver.initial_balance if use_initial_balance else receiver.balance

            if tr['message']['sender'] in account_balance_map:
                sender_balance = account_balance_map[tr['message']['sender']]

            if tr['message']['receiver'] in account_balance_map:
                receiver_balance = account_balance_map[tr['message']['receiver']]

            updated_sender_balance = sender_balance - value
            updated_receiver_balance = receiver_balance + value

            if updated_sender_balance < 0:
                self._invalid_transactions.append(tr)

            account_balance_map[tr['message']['sender']] = updated_sender_balance
            account_balance_map[tr['message']['receiver']] = updated_receiver_balance

        return account_balance_map
