# Bitcoin Address Brute-Forcing Software

This software is a **Bitcoin address brute-forcing tool** designed to generate and validate various types of Bitcoin addresses. It supports the following functionalities:

- **Address generation**: Generates all Bitcoin address types: Legacy (`1`), P2SH (`3`), and Bech32 (`bc1`).
- **Address validation**: Validates addresses against a given database, such as [Loyce's Bitcoin address list](http://addresses.loyce.club/).
- **Configurable matching**: Allows users to define how many characters from the end of addresses to include for faster validation, with a detailed explanation in the configuration file (`config.py`).
- **Parallel processing**: Utilizes multiple CPU cores for faster brute-forcing with safeguards against crashes.
- **File splitting**: Includes a splitter tool to prepare a database structure for validation by splitting address files based on their types and prefixes.
- **Crash recovery**: Captures semi-matches (partial matches) in case of unexpected crashes and logs them in a `SEMI-MATCH` file.

## Key Features

### 1. Supported Address Types
- **Legacy (P2PKH)**: Addresses starting with `1` (e.g., `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`).
- **P2SH**: Addresses starting with `3` (e.g., `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`).
- **Bech32 (Native SegWit)**: Addresses starting with `bc1` (e.g., `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080`).

### 2. Splitter for Address Database
The `splitter.py` script processes a large address database and organizes it into folders by type (`1`, `3`, `bc1`) and prefix-based files for optimized lookup. **Note:** Splitting large files can take significant time, but progress can be observed in the `DATABASE` folder as files are created.

### 3. Configurable Matching
You can adjust the substring length to control how many characters from the end of addresses are used for fast validation:
- Longer substrings increase memory usage but reduce false positives.
- See the `config.py` file for detailed explanations and examples of probability calculations.

### 4. Parallel Processing
The software supports multi-core processing. The number of CPU cores can be configured in `config.py`.

### 5. Crash Recovery
If the software finds a semi-match or a fully matched address but crashes before logging it, the result will be saved in a semi-matches file (`SEMI-MATCH.txt`) for manual verification.

## Installation

1. Clone the repository or download the source code.
2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
    ```

## Configuration

Edit the `config.py` file to customize the behavior:

- **Address type**: Choose from `legacy`, `p2sh`, `bech32`, or `all`.
- **CPU core usage**: Set `CPU_COUNT` to control the number of processes.
- **Substring length**: Modify `SUBSTRING` to define the number of characters used for matching.
- **Logging**: Adjust logging verbosity by changing `LOG_LEVEL`.

## Usage

### 1. Split Address Database
Run the splitter tool to prepare the database for validation:
```bash
python splitter.py
```

### Note: Splitting large files can take significant time. You can track progress in the DATABASE folder as files are created.


### 2. Start Brute-Forcing
Run the main brute-forcing script:
```bash
python main.py
```

This will:

- Generate Bitcoin private and public keys.
- Convert public keys into all selected Bitcoin address types.
- Match the generated addresses against the prepared database.
- Log any matches or semi-matches.

## Output Files

- **`BRUTED.txt`**: Contains fully matched Bitcoin addresses, private keys, and public keys.
- **`SEMI-MATCH.txt`**: Captures potential matches in case of a crash.
- **Splitter Output**: Folders (`1`, `3`, `bc1`) with address files named by prefix.


## Notes

1. **Memory Usage**: The substring length (`SUBSTRING`) significantly affects memory consumption. Refer to the probability table in `config.py` for optimal configurations.
2. **Performance**: Multi-core processing ensures faster address generation and validation.
3. **Safety**: If a match is found but not logged due to a crash, the address is saved in `SEMI-MATCH.txt`.
