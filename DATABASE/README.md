# DATABASE Folder

This folder is used to store the prepared structure of Bitcoin address files for the brute-forcing process.

## Instructions

1. **Download the Address File**:
   - Visit [Loyce's Bitcoin address list](http://addresses.loyce.club/) and download the file containing all Bitcoin addresses with balances.

2. **Run the Splitter**:
   - Place the downloaded file in the root directory of the project.
   - Run the `splitter.py` script to organize the addresses into structured files by type (`1`, `3`, `bc1`) and prefixes.

   ```bash
   python splitter.py
    ```
   

