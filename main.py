import multiprocessing
import hashlib
import binascii
import os
import time
import psutil
import logging
import colorlog
from ellipticcurve.privateKey import PrivateKey
from bech32 import bech32_encode, convertbits

from config import (SUBSTRING, CPU_COUNT,DATABASE_FOLDER, SEMI_MATCH_FILENAME,
                    BRUTED_FILENAME, ADDRESS_TYPE, LOG_LEVEL, IS_SAVE_SEMI_MATCH,
                    PREFIX_LENGTH_legacy, PREFIX_LENGTH_p2sh, PREFIX_LENGTH_bech32,
                    BTC_ADDRESSES_FILE)


'''================LOGGING CONFIGURATION=================='''

# Define the color scheme for each log level
log_colors = {
    'DEBUG': 'white',
    'INFO': 'cyan',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'bold_red'
}

# Create a color formatter
formatter = colorlog.ColoredFormatter(
    fmt='%(log_color)s[%(asctime)s] %(levelname)s - %(message)s',
    log_colors=log_colors,
    datefmt='%Y-%m-%d %H:%M:%S'  # Time format without commas
)

# Configure the logging
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(handler)

'''==============END LOGGING CONFIGURATION================'''

# Generate a private key (random 256-bit value)
def generate_private_key():
    """
    Generate a random private key in hexadecimal format.

    :return: Hexadecimal string of the private key.
    """
    private_key = binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
    logger.debug(f"Generated private key: {private_key}")
    return private_key

# Convert a private key to a public key
def private_key_to_public_key(private_key):
    """
    Derive the public key from a private key using elliptic curve cryptography.

    :param private_key: Hexadecimal string of the private key.
    :return: Hexadecimal string of the uncompressed public key.
    """
    pk = PrivateKey(secret=int(private_key, 16))
    public_key = '04' + pk.publicKey().toString("hex").upper()
    logger.debug(f"Generated public key: {public_key}")
    return public_key

# Convert a public key to a Legacy (P2PKH) address
def public_key_to_legacy_address(public_key):
    """
    Convert a public key to a Legacy (P2PKH) Bitcoin address.

    :param public_key: Hexadecimal string of the public key.
    :return: Legacy Bitcoin address as a string.
    """
    sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()

    versioned_key = b'\x00' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
    full_key = versioned_key + checksum

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(full_key, 'big')
    base58 = ''
    while value > 0:
        value, mod = divmod(value, 58)
        base58 = alphabet[mod] + base58

    for byte in full_key:
        if byte == 0:
            base58 = '1' + base58
        else:
            break

    return base58

# Convert a public key to a SegWit (P2SH) address
def public_key_to_p2sh_address(public_key):
    """
    Convert a public key to a SegWit (P2SH) Bitcoin address.

    :param public_key: Hexadecimal string of the public key.
    :return: P2SH Bitcoin address as a string.
    """
    sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()

    versioned_key = b'\x05' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
    full_key = versioned_key + checksum

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(full_key, 'big')
    base58 = ''
    while value > 0:
        value, mod = divmod(value, 58)
        base58 = alphabet[mod] + base58

    for byte in full_key:
        if byte == 0:
            base58 = '1' + base58
        else:
            break

    return base58

# Convert a public key to a Native SegWit (Bech32) address
def public_key_to_bech32_address(public_key):
    """
    Convert a public key to a Native SegWit (Bech32) Bitcoin address.

    :param public_key: Hexadecimal string of the public key.
    :return: Bech32 Bitcoin address as a string.
    """
    sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()

    witness_version = 0
    data = [witness_version] + list(convertbits(hashed_public_key, 8, 5, True))
    return bech32_encode("bc", data)

# Convert a public key to one or multiple Bitcoin addresses based on the specified type
def public_key_to_address(public_key):
    """
    Generate Bitcoin addresses of specified types from a public key.

    :param public_key: Hexadecimal string of the public key.
    :return: List of Bitcoin addresses.
    """
    addresses = []
    if ADDRESS_TYPE == "legacy":
        addresses.append(public_key_to_legacy_address(public_key))
    elif ADDRESS_TYPE == "p2sh":
        addresses.append(public_key_to_p2sh_address(public_key))
    elif ADDRESS_TYPE == "bech32":
        addresses.append(public_key_to_bech32_address(public_key))
    elif ADDRESS_TYPE == "all":
        addresses.append(public_key_to_legacy_address(public_key))
        addresses.append(public_key_to_p2sh_address(public_key))
        addresses.append(public_key_to_bech32_address(public_key))
    else:
        raise ValueError("Invalid address type. Use 'legacy', 'p2sh', 'bech32', or 'all'.")

    logger.debug(f"Generated addresses: {addresses}")
    return addresses

# Convert a private key to Wallet Import Format (WIF)
def private_key_to_wif(private_key):
    """
    Convert a private key to Wallet Import Format (WIF).

    :param private_key: Hexadecimal string of the private key.
    :return: WIF string.
    """
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    checksum = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    wif_key = binascii.unhexlify('80' + private_key + checksum[:8])

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(wif_key, 'big')
    base58 = ''
    while value > 0:
        value, mod = divmod(value, 58)
        base58 = alphabet[mod] + base58

    for byte in wif_key:
        if byte == 0:
            base58 = '1' + base58
        else:
            break

    return base58

# Load Bitcoin addresses from a file into memory
def load_wallets_to_memory(file_path):
    """
    Load Bitcoin addresses from a file into a set and log time and memory usage.

    :param txt_file: File containing Bitcoin addresses.
    :return: Set of address substrings.
    """
    start_time = time.time()  # Start the timer
    wallets_set = set()

    with open(file_path, 'r') as file:
        for line in file:
            address = line.strip()
            if ADDRESS_TYPE == 'legacy':
                if address.startswith('1'):
                    wallets_set.add(address[-SUBSTRING:])
            elif  ADDRESS_TYPE == 'p2sh':
                if address.startswith('3'):
                    wallets_set.add(address[-SUBSTRING:])
            elif ADDRESS_TYPE == 'bech32':
                if address.startswith('bc'):
                    wallets_set.add(address[-SUBSTRING:])
            else:
                wallets_set.add(address[-SUBSTRING:])
        logger.debug(f'FILENAME: "{file_path} | len(wallets_set) = {len(wallets_set)}')

    end_time = time.time()  # End the timer
    elapsed_time = end_time - start_time  # Calculate elapsed time

    # Get memory usage in MB
    process = psutil.Process()
    memory_usage = process.memory_info().rss / (1024 * 1024)  # RSS (Resident Set Size) in MB

    # Log the results
    logger.warning(f"Loaded {len(wallets_set)} addresses into memory.")
    logger.warning(f"Time taken: {elapsed_time:.2f} seconds.")
    logger.warning(f"Memory usage: {memory_usage:.2f} MB.")

    return wallets_set

# Save private key, public key, and address to a file
def save_to_file(filename, private_key, public_key, address):
    """
    Save private key, public key, and address information to a file.

    :param filename: Output file name.
    :param private_key: Hexadecimal private key.
    :param public_key: Hexadecimal public key.
    :param address: Bitcoin address.
    """
    wif_key = private_key_to_wif(private_key)
    data = (
        f"hex private key: {private_key}\n"
        f"WIF private key: {wif_key}\n"
        f"public key: {public_key}\n"
        f"Bitcoin address: {address}\n\n"
    )
    with open(filename, 'a') as file:
        file.write(data)

def determine_wallet_type(address):
    """
    Определяет тип кошелька и возвращает папку и длину префикса для поиска файла.
    """
    if address.startswith('1'):
        return '1', PREFIX_LENGTH_legacy
    elif address.startswith('3'):
        return '3', PREFIX_LENGTH_p2sh
    elif address.startswith('bc1'):
        return 'bc1', PREFIX_LENGTH_bech32
    else:
        return None, None  # Если тип кошелька не распознан

# Main function for generating and matching addresses
def main(database, cpu_num):
    """
    Main function to generate and match Bitcoin addresses against a database.

    :param database: Set of known address substrings.
    """
    while True:
        try:
            private_key = generate_private_key()
            public_key = private_key_to_public_key(private_key)
            addresses = public_key_to_address(public_key)
            for address in addresses:
                if address[-SUBSTRING:] in database:
                    logger.warning(f'SEMI-MATCH FOUND {address} | CPU #{cpu_num}')
                    if IS_SAVE_SEMI_MATCH:
                        save_to_file(SEMI_MATCH_FILENAME, private_key, public_key, address)

                    folder, prefix_length = determine_wallet_type(address)
                    folder_path = os.path.join(DATABASE_FOLDER, folder)
                    prefix = address[:prefix_length]
                    file_name = f"{prefix}.txt"
                    file_path = os.path.join(folder_path, file_name)

                    if os.path.exists(file_path):
                        with open(file_path, 'r') as file:
                            if address in file.read():
                                logger.critical(f"BRUTED {address} | CPU #{cpu_num}")
                                save_to_file(BRUTED_FILENAME, private_key, public_key, address)
                    else:
                        logger.error(f'ERROR: address with prefix {prefix} does not exist.')

        except Exception as e:
            logger.error(f'ERROR: {e}')


# Entry point
if __name__ == '__main__':
    logger.warning(f'CPU COUNT: {CPU_COUNT}')
    logger.warning(f'Reading database... | SUBSTRING = {SUBSTRING}')
    database = load_wallets_to_memory(BTC_ADDRESSES_FILE)

    logger.warning('Starting processes...')
    processes = []
    for cpu_num in range(CPU_COUNT):
        p = multiprocessing.Process(target=main, args=(database, cpu_num, ))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()
