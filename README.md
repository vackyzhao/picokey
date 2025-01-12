# Password Manager on RP2350

## Overview
This project implements a lightweight password manager on the RP2350 microcontroller. It supports secure password storage, AES-256 encryption, and TOTP (Time-based One-Time Password) generation. The system is equipped with a command-line interface (CLI) for user interaction and file system management.

---

## Features

- **Password Management**:
  - Secure storage of passwords with SHA-256 hashes and AES-256 encryption.
  - Change master password functionality.
  - Password verification with stored hash values.

- **File System Operations**:
  - Dual access modes for the file system: MCU and PC.
  - File management commands: `ls`, `rm`, and file querying.

- **TOTP Generation**:
  - Create and manage TOTP tokens.
  - Generate time-based OTPs for enhanced security.

- **Neofetch-like Display**:
  - ASCII art for RP2350 branding.
  - System information display including CPU, frequency, SRAM, and Flash.

---

## Commands
Below is the list of available commands:

| Command                             | Description                                                                 |
|-------------------------------------|-----------------------------------------------------------------------------|
| `help`                              | Display available commands.                                                |
| `switch_fs <mode>`                  | Switch file system control (`mcu` or `pc`).                                |
| `fs_status`                         | Show current file system control mode.                                     |
| `ls`                                | List all files and directories.                                            |
| `rm <filename>`                     | Remove a specific file.                                                    |
| `add <url>,<username>,<password>`   | Add a new entry to the encrypted password database.                        |
| `find <site>`                       | Query the database for specific website credentials.                       |
| `encrypt_db`                        | Encrypt the password database.                                             |
| `change_password`                   | Change the master password securely.                                       |
| `reset`                             | Reset the system, clearing EEPROM and Flash storage.                       |
| `exit`                              | Save data and prepare the system for shutdown.                             |
| `create_totp,<tag>,<secret>`        | Create a new TOTP token with a tag and Base32-encoded secret.              |
| `generate_totp,<tag>,<timestamp>`   | Generate a TOTP using the specified tag and timestamp.                     |

---

## Usage Guide

### Step 1: Set Master Password
1. Connect the RP2350 board to your computer via USB.
2. Open a serial terminal (e.g., Arduino Serial Monitor or PuTTY) with a baud rate of `115200`.
3. When prompted, set a master password.
4. Confirm your password to proceed.

### Step 2: Switch File System to PC Mode
1. Type the following command in the serial terminal:
   ```plaintext
   switch_fs pc
   ```
2. The system will enable file access for your PC.
3. Verify the status with:
   ```plaintext
   fs_status
   ```

### Step 3: Upload CSV Password Data
1. On your computer, open the drive mounted by the RP2350.
2. Prepare a CSV file named `passwords.csv` in the following format:
   ```csv
   "URL","Username","Password"
   "example.com","user123","pass456"
   ```
3. Copy the file to the mounted drive.
4. **Ensure to safely eject the drive from your computer**.

### Step 4: Convert to Encrypted Format
1. Switch the file system back to MCU mode:
   ```plaintext
   switch_fs mcu
   ```
2. Encrypt the database using:
   ```plaintext
   encrypt_db
   ```
3. The system will securely store your password data in an encrypted format.

### Step 5: Add and Query Entries
- **Add a new entry**:
  ```plaintext
  add "newsite.com","newuser","newpass"
  ```
- **Query an entry by site**:
  ```plaintext
  find "example"
  ```

---

## Installation
1. Clone this repository or copy the source files.
2. Install required Arduino libraries:
   - `Hash.h`
   - `AESLib.h`
   - `FatFS.h`
   - `FatFSUSB.h`
   - `EEPROM.h`
   - `Crypto.h`
   - `SHA256.h`
3. Set up the RP2350 development environment.
4. Upload the code to the RP2350 board.

---

## Example ASCII Art Display
```plaintext
FatFS initialization done.
USB drive mode is disabled by default.
EEPROM initialized.
Password is already set.
Enter your password to verify:
Password verified successfully!

   /\__\     /\  \     /\__\    /\__\      Board        : RP2350
  /::L_L_   _\:\  \   /:/  /   /:/ _/_     CPU Arch     : ARM Cortex-M33
 /:/L:\__\ /\/::\__\ /:/__/   /::-"\__\    CPU Frequency: 150 MHz
 \/_:/  / \::/\/__/ \:\  \   \;:;-",-"     SRAM         : 264 KB
   /:/  /   \:\__\    \:\__\   |:|  |      Flash        : 4 MB
   \/__/     \/__/     \/__/    \|__|
    ___       ___       ___
   /\  \     /\  \     /\  \
  /::\  \   /::\  \    \:\  \
 /:/\:\__\ /::\:\__\   /::\__\
 \:\ \/__/ \/\::/  /  /:/\/__/
  \:\__\     /:/  /  /:/  /
   \/__/     \/__/   \/__/
=====================================
Welcome to RP2350 Terminal!
Type 'help' to see available commands.
> help
Available commands:
  help          - Show this help message
  switch_fs mcu - Switch file system block to MCU
  switch_fs pc  - Switch file system block to PC
  fs_status     - Query current file system block status
  ls            - List all files and directories
  rm <filename> - Remove a specified file
  add           - Add a new entry to the database (<url>,<username>,<password>)
  find          - Query the password database for a specific website
  encrypt_db    - Encrypt the password database file (requires key input)
  change_password - Change the master password
  reset         - Reset system and clear data
  exit          - Exit the program and save data
> 
```

---

## Security Highlights
- **Master Password**: Secured using SHA-256 hashing and stored in EEPROM.
- **File Encryption**: AES-256 encryption for password databases with random IVs.
- **Salted Hashing**: Enhanced security against dictionary attacks using random salts.

---

## License
This project is released under the MIT License.
