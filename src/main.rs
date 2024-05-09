// Import the necessary modules and packages
use ring::aead; // The 'ring' crate provides cryptographic operations
use ring::error::Unspecified; // This is a type for unspecified errors from the 'ring' crate
use serde_json; // This crate is used for serializing and deserializing JSON data
use std::env; // This module provides access to the process's environment
use std::fs::File; // This module provides a way to work with the file system
use std::io::{self, Read, Write}; // This module provides a way to perform input/output operations

// Define an enumeration for possible encryption errors
#[derive(Debug)]
enum EncryptError {
    IoError(io::Error),     // An I/O error
    AeadError(Unspecified), // An error from the AEAD (Authenticated Encryption with Associated Data) operation
}

// Implement the From trait for io::Error to allow for easy conversion to EncryptError
impl From<io::Error> for EncryptError {
    fn from(error: io::Error) -> Self {
        EncryptError::IoError(error)
    }
}

// Implement the From trait for Unspecified to allow for easy conversion to EncryptError
impl From<Unspecified> for EncryptError {
    fn from(error: Unspecified) -> Self {
        EncryptError::AeadError(error)
    }
}

// Implement the Display trait for EncryptError to allow for easy printing of the error
impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::IoError(err) => write!(f, "IO error: {}", err),
            EncryptError::AeadError(err) => write!(f, "AEAD error: {}", err),
        }
    }
}

// Implement the Error trait for EncryptError to allow for easy error handling
impl std::error::Error for EncryptError {}

// The main function where the program starts execution
fn main() {
    // Collect the command line arguments into a vector
    let args: Vec<String> = env::args().collect();
    // Check if the correct number of arguments are provided
    if args.len() < 4 {
        println!("Usage: encryptor <encrypt|decrypt> <password> <file>");
        return;
    }

    // @function: Extract the command, password, file path, and nonce from the arguments
    // Note the these variables below are being assigned borrowed references to the strings or slices of strings in the vector which is returned from
    // env::args().collect() which in turn is owned by the args variable. We can therefore call the vector ie. the Vec<String> the args vector.
    // But it's good to know how it becomes that anyway.

    let command = &args[1];
    let password = &args[2];
    let file_path = &args[3];
    let nonce_str = &args[4];

    // @dev: Efe
    // Parse the nonce string into a vector of bytes.
    // This is done to allow for easy deserialization of the nonce which is a vector of bytes sent in as a string
    // passed by the user as the fourth command line argument.
    // So, we go from a string of JSON text representing 12 bytes visually and then back to a vector of bytes again
    let nonce: Vec<u8> = serde_json::from_str(nonce_str)
        .map_err(|e| {
            println!("Error parsing nonce: {}", e);
            EncryptError::AeadError(Unspecified)
        })
        .unwrap();

    /*
        @dev: Efe
        So are we just type-casting with the serde_json::from_str() method?
        Not exactly. The serde_json::from_str() function in Rust is not just type-casting, it’s actually performing deserialization.
        In Rust, type casting is a way to convert a value from one data type to another. For example, converting an integer to a float.
        This is a simple conversion and doesn’t involve any complex processing.
        On the other hand, serde_json::from_str() is a function provided by the serde_json crate that deserializes a JSON string into a Rust data structure.
        Deserialization is a more complex process than type-casting. It involves parsing the JSON string, understanding its structure, and then creating the
        corresponding Rust data structure.
        In the case of serde_json::from_str(nonce_str), the function is trying to parse the nonce_str (which is a JSON string) and convert it into a Vec<u8>,
        which is a vector of bytes. If the nonce_str is not a valid JSON string, or if it doesn’t match the structure of a Vec<u8>, the function will return an error.
        So, while both type-casting and deserialization involve some form of conversion, they are used for different purposes and involve different levels of
        complexity.
    */

    /*
        @dev: Efe
        Let break unwrap() down into its parts:
        serde_json::from_str(nonce_str) is a function that tries to deserialize a JSON string (nonce_str) into a Rust data structure (Vec<u8> in this case).
        This function returns a Result type. If the deserialization is successful, it returns Ok(value) where value is the deserialized value (Vec<u8>).
        If the deserialization fails (for example, if nonce_str is not a valid JSON string), it returns Err(e) where e is the error that occurred.
        The map_err() function is then called on this Result. If the Result is Err(e), map_err() transforms the Err(e) into a new error
        EncryptError::AeadError(Unspecified). If the Result is Ok(value), map_err() does nothing and the Ok(value) is passed through.
        Finally, unwrap() is called on the Result. If the Result is Ok(value), unwrap() returns the value. If the Result is Err(e), unwrap() causes the program
        to panic and print a debug message. So, in this code, unwrap() is being used to get the deserialized value (Vec<u8>) if the deserialization was successful,
        or to cause the program to panic if the deserialization failed. It’s a way of saying “give me the value if it’s there, but stop the program if there was
        an error”. However, using unwrap() in this way can lead to program crashes and is generally not recommended for production code. Instead, it’s better to
        handle potential errors explicitly. For example, you could use a match statement to handle both the Ok and Err cases.
    */

    // A 'stream' is a sequence or flow of data from one place to another in a continuous manner.
    // Streams are used in programming for input/output operations, where data is read from or written to a storage medium
    // (like memory, a file, or a network connection) in a continuous flow.

    // A 'stream of bytes', also known as a byte stream, is a sequence of bytes.
    // Each byte in the stream is an 8-bit quantity. The term "octet stream" is sometimes used interchangeably with byte stream.

    // In the context of a byte stream, the bytes can represent any kind of data, such as text, numbers, or binary data.
    // The interpretation of the bytes depends on the context and the intended use.
    // For example, a byte stream could be interpreted as text (in various encodings), as integer numbers (in big or little endian),
    // or even as a file (like a zip file).

    // In your Rust code, 'serde_json::from_str(nonce_str).unwrap()' is deserializing a JSON string into a byte stream (a 'Vec<u8>'),
    // where each byte is a unit of binary data.

    // Perform the encryption or decryption based on the command
    //
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
    // @dev: Efe
    // Explanation:
    // The above code is checking the value of `command`. If the value is "encrypt", the code will call the `encrypt` function.
    // If the value is "decrypt", the code will call the `decrypt` function.
    // If the value is anything else, the code will print "Invalid command".
    // It is the equivalent of a switch statement in other languages like Javascipt.
    //
    // 1. `match command.as_str() { ... }`: This is a match expression, similar to a switch statement in other languages.
    //    It's checking the string value of `command`.
    // 2. `"encrypt" => { ... }` and `"decrypt" => { ... }`: These are match arms. If `command.as_str()` equals "encrypt" or "decrypt",
    //    the code inside the curly braces `{}` will be executed.
    // 3. `if let Err(err) = encrypt(password, file_path, &nonce) { ... }`: This is an "if let" statement. It's used for pattern matching.
    //    Here, it's trying to match the result of `encrypt(password, file_path, &nonce)` with `Err(err)`. If the `encrypt` function
    //    returns an `Err`, it will be matched and the error will be bound to `err`, and the code inside the curly braces `{}` will be executed.
    // 4. `println!("Encryption error: {}", err);`: This line will be executed if the `encrypt` function returns an `Err`.
    //    It prints the error message to the console.
    // 5. `_ => println!("Invalid command"),`: The underscore `_` is a catch-all pattern that matches anything. If `command.as_str()`
    //    is neither "encrypt" nor "decrypt", this match arm will be executed and it will print "Invalid command" to the console.

    // @dev: Efe
    // @topic: Understanding the `if let` statement
    // The `if let` statement in Rust is used for both calling the function and handling the potential error that might be returned by the function.
    // - The `encrypt(password, file_path, &nonce)` or `decrypt(password, file_path, &nonce)` function is called within the `if let` statement.
    // - These functions return a `Result` type. If the operation was successful, they return `Ok(value)`. If there was an error, they return `Err(err)`.
    // - The `if let Err(err) = ...` syntax is used to check if the function returned an `Err(err)`. If it did, the `err` inside `Err(err)` is bound to the `err` variable in the `if let` statement, and the code inside the curly braces `{}` is executed.
    // - If the function returned `Ok(value)`, the `if let` statement does nothing, and the program continues to the next line of code.
    // The `match` statement, on the other hand, is used to determine which function (`encrypt` or `decrypt`) should be called based on the `command` string.
    // It's not directly involved in error handling. That's the job of the `if let` statement inside each `match` arm.
}

// Function to encrypt a file
// @dev: Efe
// &str is a borrowed string slice also called a string slice. It's a reference to a string.
// str is a string. It's an owned string.
// &[u8] is a slice of bytes. It's a reference to a byte array.
// In this case these params are borrowed from the args variable in the main function. ie. the args variable owns the arguments while the main function owns the args variable.
fn encrypt(password: &str, file_path: &str, nonce: &[u8]) -> Result<(), EncryptError> {
    // Open the file and read its contents into a vector
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();

    // file.read_to_end(&mut contents)?: This method reads the entire contents of a file into a byte vector (Vec<u8>).
    // This is useful when you’re working with binary data or when you need the raw bytes from the file.
    // fs::read_to_string(file_path): This function reads the entire contents of a file into a String.
    // This is useful when you’re working with text data, as it allows you to easily work with the contents as a String.
    // The concept of working with raw bytes is particularly relevant to encryption and decryption because these operations often deal with binary data.

    // When you’re encrypting or decrypting data, you’re usually working at a low level where you need to manipulate the raw bytes of the data.
    // This is because encryption algorithms operate on binary data, transforming the input bytes into a different set of output bytes. Similarly,
    // decryption algorithms reverse this process, converting the encrypted bytes back into their original form.

    // On the other hand, when you’re reading the number of lines in a text file, you’re typically working with higher-level text data, not raw binary data.
    // Each line of text in a file is represented as a sequence of characters, and you can count the number of lines by counting the number of newline characters.
    // This operation doesn’t require dealing with the raw bytes of the file, so the concept of working with byte streams or raw bytes is less applicable in this context.

    // In summary, whether you need to work with raw bytes or higher-level data structures depends on the nature of the task at hand. For low-level tasks
    // like encryption and decryption, working with raw bytes is often necessary. For higher-level tasks like counting lines in a text file, working with
    // text data is usually more appropriate.

    // Creating a buffer to hold the encrypted contents
    file.read_to_end(&mut contents)?;

    // Create a new instance of an unbound key using the AES_256_GCM algorithm and the password bytes.
    // The `new` function returns a `Result` type, so the `?` operator is used to propagate any potential error.
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, password.as_bytes())?;

    // Create a new instance of a less safe key from the unbound key.
    // The `LessSafeKey` is a wrapper around `UnboundKey` that can be used for encryption and decryption operations.
    // In programming, a wrapper is a class, function, or data structure that contains (or “wraps”) another item to provide a
    // simpler or more compatible interface.
    let key = aead::LessSafeKey::new(key);

    // @terminology: In place” is a term used in programming to describe an operation that modifies data directly in the memory where it already resides,
    // instead of creating a copy of the data and performing the operation on the copy.

    // When an operation is performed “in place”, it means that the original data is modified. This can be more efficient because it avoids the need to
    // allocate additional memory for a copy of the data. However, it also means that the original data is lost, because it has been overwritten by the
    // result of the operation.

    // In this Rust code, the seal_in_place_append_tag and open_in_place methods from the ring crate are examples of in-place operations. They encrypt
    // and decrypt data directly in the buffer where the data already resides, instead of creating a new buffer for the encrypted or decrypted data.
    // This can make the code more efficient, especially when working with large amounts of data. I hope this helps!

    // Encrypt the contents in place and append the authentication tag
    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::empty(),
        &mut contents,
    )?;

    // Write the encrypted contents to a new file
    let mut encrypted_file = File::create(format!("{}.enc", file_path))?;
    encrypted_file.write_all(&contents)?;

    Ok(())
}

// Function to decrypt a file
fn decrypt(password: &str, file_path: &str, nonce: &[u8]) -> Result<(), EncryptError> {
    // Open the file and read its contents into a vector
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Create a new AES-256-GCM key from the password
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, password.as_bytes())?;
    let key = aead::LessSafeKey::new(key);

    // Decrypt the contents in place
    key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::empty(),
        &mut contents,
    )?;

    // Determine the file path for the decrypted file
    let decrypted_file_path = if let Some(index) = file_path.rfind('.') {
        // Remove the extension from the file name
        let (name_without_extension, _) = file_path.split_at(index);
        name_without_extension.to_string()
    } else {
        // If there's no extension, use the original name
        file_path.to_string()
    };
    // @explanation:
    // `if let Some(index) = file_path.rfind('.')`: This line is using the `rfind` method to search for the last occurrence of the period character (`.`) in `file_path`,
    // which usually indicates the start of the file extension. If a period is found, its index in the string is returned as `Some(index)`.
    // If no period is found, `rfind` returns `None`.

    // `let (name_without_extension, _) = file_path.split_at(index);`: If a period was found, this line splits the `file_path` string into two at the index of the period.
    // The part before the period (the file name without the extension) is assigned to `name_without_extension`,
    // and the part after the period (the file extension) is ignored (`_` is a placeholder for ignored values in Rust).

    // `name_without_extension.to_string()`: This line converts `name_without_extension` from a string slice (`&str`) to a `String` and returns it.
    // This will be the value of `decrypted_file_path`.

    // `file_path.to_string()`: If no period was found in `file_path` (i.e., the file has no extension), this line is executed.
    // It converts `file_path` from a string slice (`&str`) to a `String` and returns it. This will be the value of `decrypted_file_path`.

    // So, in summary, this code snippet is determining the path for the decrypted file. If the encrypted file has an extension,
    // it removes the extension to get the original file name. If the encrypted file has no extension, it uses the encrypted file's name as is.

    // @explanation: Why need to use `to_string()` for `name_without_extension` and `file_path`?
    // In this program, the conversion from a string slice (&str) to an owned String is necessary because of the way the decrypted_file_path is used below.
    // The decrypted_file_path is determined within the decrypt function and is then used to create a new file with File::create(decrypted_file_path)?.
    // The File::create function requires its argument to be an owned String or something that can be converted into an owned String. A string slice (&str)
    // would not suffice here because it’s just a borrowed reference, and File::create needs ownership of its argument.
    // Moreover, the decrypted_file_path is created based on the file_path argument to the decrypt function. If I were to use a string slice that points
    // into file_path, it would be tied to the lifetime of file_path. If file_path is modified or goes out of scope, the string slice would no longer be valid.
    // By creating an owned String, I ensure that decrypted_file_path is valid for as long as it needs to be.

    // Write the decrypted contents to a new file
    let mut decrypted_file = File::create(decrypted_file_path)?;
    decrypted_file.write_all(&contents)?;

    Ok(())
}
