# picokey
Password Manager on RP2350
Overview

This project implements a lightweight password manager on the RP2350 microcontroller. It supports secure password storage, AES-256 encryption, and TOTP (Time-based One-Time Password) generation. The system is equipped with a command-line interface (CLI) for user interaction and file system management.
Features

    Password Management:
        Secure storage of passwords with SHA-256 hashes and AES-256 encryption.
        Change master password functionality.
        Password verification with stored hash values.

    File System Operations:
        Dual access modes for the file system: MCU and PC.
        File management commands: ls, rm, and file querying.

    TOTP Generation:
        Create and manage TOTP tokens.
        Generate time-based OTPs for enhanced security.

    Neofetch-like Display:
        ASCII art for RP2350 branding.
        System information display including CPU, frequency, SRAM, and Flash.

Commands

Below is the list of available commands:
Command	Description
help	Display available commands.
switch_fs <mode>	Switch file system control (mcu or pc).
fs_status	Show current file system control mode.
ls	List all files and directories.
rm <filename>	Remove a specific file.
add <url>,<username>,<password>	Add a new entry to the encrypted password database.
find <site>	Query the database for specific website credentials.
encrypt_db	Encrypt the password database.
change_password	Change the master password securely.
reset	Reset the system, clearing EEPROM and Flash storage.
exit	Save data and prepare the system for shutdown.
create_totp,<tag>,<secret>	Create a new TOTP token with a tag and Base32-encoded secret.
generate_totp,<tag>,<timestamp>	Generate a TOTP using the specified tag and timestamp.
Installation

    Clone this repository or copy the source files.
    Install required Arduino libraries:
        Hash.h
        AESLib.h
        FatFS.h
        FatFSUSB.h
        EEPROM.h
        Crypto.h
        SHA256.h
    Set up the RP2350 development environment.
    Upload the code to the RP2350 board.

Usage

    Connect the RP2350 board to your computer via USB.
    Open a serial terminal (baud rate: 115200).
    Follow the on-screen instructions to set or verify the master password.
    Use the CLI commands to manage files, passwords, and generate TOTPs.

Security Highlights

    Master Password: Secured using SHA-256 hashing and stored in EEPROM.
    File Encryption: AES-256 encryption for password databases with random IVs.
    Salted Hashing: Enhanced security against dictionary attacks using random salts.

Example ASCII Art Display

   /\__\     /\  \     /\__\    /\__\  
  /::L_L_   _\:\  \   /:/  /   /:/ _/_ 
 /:/L:\__\ /\/::\__\ /:/__/   /::-"\__\
 \/_:/  / \::/\/__/ \:\  \   \;:;-",-  
   /:/  /   \:\__\    \:\__\   |:|  |  
   \/__/     \/__/     \/__/    \|__|  
======================================
Board        : RP2350
CPU Arch     : ARM Cortex-M33
CPU Frequency: 150 MHz
SRAM         : 264 KB
Flash        : 4 MB
======================================

Future Work

    Add support for advanced encryption algorithms.
    Implement a graphical interface for easier management.
    Optimize TOTP token storage and retrieval.

License

This project is released under the MIT License.
