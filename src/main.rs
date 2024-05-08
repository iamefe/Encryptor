// use rand::{rngs::OsRng, RngCore};
use ring::aead;
use ring::error::Unspecified;
use serde_json;
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};

#[derive(Debug)]
enum EncryptError {
    IoError(io::Error),
    AeadError(Unspecified),
}

impl From<io::Error> for EncryptError {
    fn from(error: io::Error) -> Self {
        EncryptError::IoError(error)
    }
}

impl From<Unspecified> for EncryptError {
    fn from(error: Unspecified) -> Self {
        EncryptError::AeadError(error)
    }
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::IoError(err) => write!(f, "IO error: {}", err),
            EncryptError::AeadError(err) => write!(f, "AEAD error: {}", err),
        }
    }
}

impl std::error::Error for EncryptError {}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: encryptor <encrypt|decrypt> <password> <file>");
        return;
    }

    let command = &args[1];
    let password = &args[2];
    let file_path = &args[3];
    let nonce_str = &args[4];

    let nonce: Vec<u8> = serde_json::from_str(nonce_str)
        .map_err(|e| {
            println!("Error parsing nonce: {}", e);
            EncryptError::AeadError(Unspecified)
        })
        .unwrap();

    match command.as_str() {
        "encrypt" => {
            if let Err(err) = encrypt(password, file_path, &nonce) {
                println!("Encryption error: {}", err);
            }
        }
        "decrypt" => {
            if let Err(err) = decrypt(password, file_path, &nonce) {
                println!("Decryption error: {}", err);
            }
        }
        _ => println!("Invalid command"),
    }
}

fn encrypt(password: &str, file_path: &str, nonce: &[u8]) -> Result<(), EncryptError> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, password.as_bytes())?;
    let key = aead::LessSafeKey::new(key);

    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::empty(),
        &mut contents,
    )?;

    let mut encrypted_file = File::create(format!("{}.enc", file_path))?;
    encrypted_file.write_all(&contents)?;

    Ok(())
}

fn decrypt(password: &str, file_path: &str, nonce: &[u8]) -> Result<(), EncryptError> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, password.as_bytes())?;
    let key = aead::LessSafeKey::new(key);

    key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::empty(),
        &mut contents,
    )?;

    // let mut decrypted_file = File::create(format!("{}.dec", file_path))?;
    // decrypted_file.write_all(&contents)?;

    let decrypted_file_path = if let Some(index) = file_path.rfind('.') {
        // Remove the extension from the file name
        let (name_without_extension, _) = file_path.split_at(index);
        name_without_extension.to_string()
    } else {
        // If there's no extension, use the original name
        file_path.to_string()
    };

    let mut decrypted_file = File::create(decrypted_file_path)?;

    decrypted_file.write_all(&contents)?;

    Ok(())
}
