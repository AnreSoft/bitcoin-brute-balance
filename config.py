import multiprocessing
import logging

'''==================USER CONFIGURATION=================='''

SUBSTRING = 5  # Number of characters for address substring matching. Higher values require more memory.
CPU_COUNT = multiprocessing.cpu_count()  # Number of processes. Use multiprocessing.cpu_count() for all available CPU cores.

DATABASE_FOLDER = 'DATABASE'  # File containing Bitcoin addresses (e.g., http://addresses.loyce.club/).
SEMI_MATCH_FILENAME = 'SEMI-MATCH.txt'  # File to save semi-matches (partial matches for safety).
BRUTED_FILENAME = 'BRUTTED.txt'  # File to save fully matched addresses.
BTC_ADDRESSES_FILE = "Bitcoin_addresses.txt"

ADDRESS_TYPE = 'legacy'  # Address type: 'legacy' - 1, 'p2sh' - 3, 'bech32' - bc1, or 'all'.
LOG_LEVEL = logging.WARNING  # Logging level: DEBUG for full info, INFO for all generated addresses, WARNING for semi-matches, CRITICAL for full matches.
IS_SAVE_SEMI_MATCH = False

PREFIX_LENGTH_legacy = 2 # startwith "1"
PREFIX_LENGTH_p2sh =   3 # startwith "3"
PREFIX_LENGTH_bech32 = 6 # startwith "bc1"


'''================END USER CONFIGURATION================'''


'''
Probability of Generating a Bitcoin Address with a Specific Ending

The probability of generating a Bitcoin address with a specific SUBSTRING of length `n` is given by:

    P = 1 / (58^n)

Where:
- `n` is the length of the desired substring,
- `58` is the size of the Base58 alphabet used in Bitcoin addresses.

| SUBSTRING Length (n) | Probability (P)                | Approximate Attempts for 50% Success |
|-----------------------|-------------------------------|--------------------------------------|
| 1                     | 1 / 58 ≈ 0.017 (1.7%)         | 40                                   |
| 2                     | 1 / (58^2) ≈ 0.0003           | 3,364                                |
| 3                     | 1 / (58^3) ≈ 0.000005         | 195,112                              |
| 4                     | 1 / (58^4) ≈ 0.00000008       | 11,311,388                           |
| 5                     | 1 / (58^5) ≈ 0.0000000014     | 655,747,031                          |
| 6                     | 1 / (58^6) ≈ 0.00000000002    | 38,031,597,540                       |
| 7                     | 1 / (58^7) ≈ 0.0000000000003  | 2,205,830,676,541                    |
| 8                     | 1 / (58^8) ≈ 0.000000000000005| 127,538,962,478,340                  |

Each additional character in the substring increases the difficulty of finding a match by 58 times, as the number of possible combinations grows exponentially.
'''