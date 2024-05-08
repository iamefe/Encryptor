# Encryptor: A simple Rust-based CLI for encrypting and decrypting files (experimental)

## Overview

Encryptor is a command-line tool written in Rust for encrypting and decrypting files using the AES-GCM Authenticated Encryption with Associated Data (AEAD) cipher. It provides a simple and straightforward way to protect sensitive files on your system.

## Features

- Encrypts and decrypts files using AES-GCM.
- Supports encryption and decryption of any type of file.
- Easy-to-use CLI interface.
- Experimental: Use with caution in production environments.

## Usage

To encrypt a file:

```shell
cargo run encrypt <password> <file_path> <nonce>
```

For example:

```shell
cargo run encrypt 12345678901234567890123456789012 test.txt "[246, 231, 118, 136, 232, 16, 173, 214, 11, 241, 220, 114]"
```

To decrypt a file encrypted by this CLI:

```shell
cargo run decrypt <password> <file_path> <nonce>
```

For example:

```shell
cargo run decrypt 12345678901234567890123456789012 test.txt.enc "[246, 231, 118, 136, 232, 16, 173, 214, 11, 241, 220, 114]"
```

## Arguments

password : The password you wish to use for encryption/decryption.

file_path: The path to the file to be encrypted/decrypted.

file_path.enc: The path to the encrypted file to be decrypted.

nonce: The nonce value you wish to use for ecryption and decryption. Must be provided in the format [byte0, byte1, ..., byte12] ie. an array of 12 numbers (see examples above).

### Note

The password and nonce for encrypting a file will be required to be the same ones for decrypting its encrypted form.

## Getting Started

- Clone this repository to your local machine.
- Navigate to the project directory.
- Install Rust if you haven't already (https://www.rust-lang.org/tools/install).
- Run cargo build to build the project.
- Follow the usage instructions above to encrypt or decrypt files.

## Security Considerations

- Always use a strong and unique password.
- Keep your password secure and never share it with unauthorized users.
- Be cautious when using experimental software in production environments.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```

Feel free to modify and expand upon this template to suit your needs!

```
