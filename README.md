# Command-Line Password Manager

## Disclaimer
This project was done for a grad school class. While I am making this code public for educational purposes, if you are working on a similar project for a class, you are not authorized to copy code for your project unless it is permitted by the academic integrity code of your school and you include a reference to this project.

## Description
Python script that stores (Username, Password) pairs in a sqlite3 database. The script takes as input a master password, which is used to derive key material that is then used to encrypt each password. In addition, the sqlite3 database is also encrypted with a different key.

## Requirements
* Python 2.7.11+
* PyCrypto 2.6.1

## Design
The implementation of this project considered the following principles:
* Using cryptography standards instead of trying to come up with a new algorithm.
* Using existing libraries instead of trying to write my own implementation of the cryptographic primitives. In this case, the library used for cryptographic functions was PyCrypto.

The script is executed from the command line and input is provided using the supported flags. One of the flags (i.e., the `--action` or `-a` flag) specifies which action will be executed. The supported actions are:
* **AddEntry**: This action is used to insert a (Username, Password) record into the sqlite3 database. The password is encrypted before it is stored. The details of the encryption process will be discussed later in this write-up.
* **CheckEntry**: This action is used to check if the provided username exists in the database and if the password matches the one stored in the database.
* **GenerateKey**: This action is used to generate a key file that contain the keys used to encrypt and authenticate the database file. Details of this process are provided later. The generated key file is also encrypted with a key that is derived from the master password provided.
* **GetPassword**: This action is used to get the plaintext password from the user provided as input.

The way the passwords are stored by this script is different from the way shadow files work. Shadow files store the hash of a password instead of storing it in cleartext [17]. This script stores an encrypted version of the password instead of storing a hash. Storing the encrypted version of the password allows the script to decrypt it to be able to provide the plaintext version to the user as one of the supported features. This is exactly what the supported action `GetPassword` does. It retrieves the encrypted version of the password from the database, decrypts it, and shows the plaintext to the user.

#### Database File
The database file contains only the passwords table. This table contains two columns: the username column and the password column. See `create_passwords_table()` in the source code for the details.

## Cryptography Details
### Keys
This section describes the different keys used by the script, what their purpose is, how they are used, and if they are stored, details about how they are stored.

#### Key Derivation Function
This script uses PBKDF2, which is a standard password-based key derivation function. Password-based key derivation functions can be used to deterministically generate key material from a password [7].

#### Master Password
The master password is provided as input to the program using the flag `--master-password` or `-mp`. This master password is not stored anywhere. It should be provided by the user of the script. The master password is used as input to PBKDF2 to derive key material that is used to encrypt the database and the passwords.

In the `generate_key_file()` function, a pseudorandom salt and the master password are used as input to the password-based key derivation function to generate two keys. NIST specifies that the salt must be at least 128 bits [7], which is the length used by this script. The random salt is stored with the ciphertext to be able to derive the keys to decrypt the key file. The implication of this is that derived keys generated using the same master password will be different because of the random salt. The `read_keys_from_file()` function uses this master password to derive the same set of keys that were used to encrypt the key file.
* **key_file_encryption_key**: This key is used to encrypt the contents of the key file using AES with 256-bit key. Details of the key file are provided in the next section.
* **key_file_authentication_key**: This key is used to authenticate the ciphertext that is obtained after encrypting the contents of the key file. For authentication, this script uses HMAC-SHA256. HMAC is a standard Keyed-Hash Message Authentication Code [13].

In the `encrypt_and_insert_password()` function, a pseudorandom salt and the master password are used as input to the password-based key derivation function to generate two keys:
* **password_encryption_key**: This key is used to encrypt a password before it is stored in the database. Every time a record is inserted, a different random salt is used to derive a set of keys. This means that each password is encrypted with a different key. The salt is stored with the ciphertext to be able to reverse this process to decrypt the password.
* **password_authentication_key**: This key is used to authenticate the ciphertext that is obtained after encrypting the password. The MAC used to authenticate the password ciphertext is HMAC-SHA256.

**A note about providing the master password as a command line argument**
The obvious downside of this is that someone could look over the user’s shoulder and see what the master password is. However in this case, the impact is mitigated by the fact that without having possession of the key file as well, the master password by itself will not be able to be used to decrypt the password database. In addition, the advantage of using a command line argument to provide this password is that the python script can be called as part of another script to automate password reading/writing tasks.

#### Key File
In the `generate_key_file()` function, 512 pseudorandom bits are generated, encrypted and authenticated using key_file_encryption_key and key_file_authentication key respectively, and stored in the key file. These 512 bits are used as two cryptographic keys. The `read_keys_from_file()` function returns these two keys.
* **database_encryption_key**: This key is used to encrypt the database right before the script finishes executing. Encrypting the database serves as an extra layer of confidentiality. This also prevents someone from looking at the file to see the list of usernames.
* **database_authentication_key**: In the same way that it is described above for the other set of keys, this key is used to authenticate the ciphertext that is obtained after encrypting the database. The MAC used to authenticate the password ciphertext is HMAC-SHA256.

**Why Am I Adding Authentication In Addition to Encryption**
Authentication is used to provide integrity in addition to confidentiality. This allows the program to detect if an attacker tampered with the ciphertext. According to Katz and Lindell: *“It is best practice to always encrypt and authenticate by default; encryption alone should not be used unless there are compelling reasons to do so (such as implementations on severely resource-constrained devices) and, even then, only if one is absolutely sure that no damage can be caused by undetected modification of data.”* [5]

**Why Am I Using So Many Keys?**
The reason is to follow one of the cryptographic principles: *“different security goals should always use different keys.”* [5] This means that the keys used for encryption should be different from the keys used for authentication. Also following the same principle, the key to encrypt the database should be different from the key used to encrypt passwords. This script even uses a different key to encrypt each password. This is because the key used to encrypt a password is derived from the master password and a random salt. The random salt is different each time that the set of keys are generated, so a different key is created.

### Block Cipher
The block cipher used by this script is AES with 256-bit keys. AES stands for Advanced Encryption Standard and it is one of the cryptography standards that was announced by NIST [1].

The script supports the following cipher block modes: Electronic Codebook (ECB), Cipher Block Chaining (CBC), and Counter (CTR).

**IMPORTANT**: Do not use ECB mode to protect your passwords. This mode is implemented for academic purposes only, but it is not a secure mode.

### Padding
ECB and CBC modes expect the length of the plaintext to be a multiple of the block size. This means that if the length of the plaintext does not meet that requirement, the final block needs to be padded. For this, I also followed the best practice of using standards as opposed to inventing something for this program. The padding mechanism chosen was PKCS5 padding as described in [16].

### A Note About Brute-forcing
Brute-force is something that attackers use to attempt to crack passwords when they are stored as a hash. Because the hashing algorithm is public, an attacker can hash a password guess and compare it to the one stored in the password file. In this case, brute-forcing wouldn’t be of much help because the attacker needs the key to be able to make a guess which the attacker could then encrypt and compare to the value stored in the database. Even in this scenario, that wouldn’t work, because multiple encryptions of the same plaintext result in a different ciphertext due to the random IV. Also, if the attacker has the key, then it makes no sense to guess since the attacker could just decrypt the passwords.

Having said that, there is something to consider when an encrypted password is stored as opposed to a hashed password. Similar to the way a salt is used to store passwords so that hashing the same password results in a different hash [8], it is important to ensure that encryptions of the same plaintext result in a different ciphertext. Deterministic encryption is not secure against some cryptographic attacks [5]. This script accomplishes that in two ways: First, a different key is used to encrypt different passwords (see Cryptographic Details section). This is true for all cipher block modes supported by this script. Second, a random IV is generated for each encryption, which ensures that when CBC mode is used, even if the same key is used to encrypt the password (which it isn’t), the ciphertext would be different each time.

## How To Use The Script
The action is provided as input using the flag `--action` or its short version `-a`.

**Generate Key File**
The first time the script is used a key file should be generated (see Cryptography Details section for information about what this file contains and how it is used). The action to generate a key file is `GenerateKey` and it has the following required arguments:
* **--key-file**, **-k**: argument to specify the name of the key file to generate.
* **--master-password**, **-mp**: argument to provide the master password.

The command to generate a key file looks like this:
`$ ./pwd-manager.py -a GenerateKey -k <path to key file> -mp <master password>`

**Add Entry**
The AddEntry action is used to insert a (Username, Password) record into the database file. The password is encrypted as described in the Cryptography Details section. The ciphertext is then encoded using Base64 and stored in the database. The AddEntry action has the following required arguments:
* **--key-file**, **-k**: argument to specify the name of the key file to generate.
* **--master-password**, **-mp**: argument to provide the master password.
* **--database**, **-d**: argument to specify the name of the database file. If the database does not exist, it gets created the first time the script is executed with an action other than GenerateKey.
* **--mode**, **-m**: cipher block mode of operation. Supported modes are ECB, CBC, and CTR. The mode used to check an entry or get the password of a specific user has to be the same that it was used to insert that entry to the database. Other than that, different modes can be used to insert records for different users into the database.
* **--username**, **-u**: the username.
* **--password**, **-p**: the password for the username provided.

The command to add an entry to the database looks like this:
`$ ./pwd-manager.py -a AddEntry -k <path to key file> -mp <master password> -d <path to database file> -m <mode> -u <username> -p <password>`

**Check Entry**
The CheckEntry action is used to check if a username exists in the database and to check if the password matches the one stored in the database. The CheckEntry action has the following required arguments:
* **--key-file**, **-k**: argument to specify the name of the key file to generate.
* **--master-password**, **-mp**: argument to provide the master password.
* **--database**, **-d**: argument to specify the name of the database file. If the database does not exist, it gets created the first time the script is executed with an action other than GenerateKey.
* **--mode**, **-m**: cipher block mode of operation. Supported modes are ECB, CBC, and CTR. The mode used to check an entry or get the password of a specific user has to be the same that it was used to insert that entry to the database. Other than that, different modes can be used to insert records for different users into the database.
* **--username**, **-u**: the username.

The command to add an entry to the database looks like this:
`$ ./pwd-manager.py -a CheckEntry -k <path to key file> -mp <master password> -d <path to database file> -m <mode> -u <username> -p <password>`

**Get Password**
The GetPassword action is used to get the plaintext password of the user provided as input. The GetPassword action has the following required arguments:
* **--key-file**, **-k**: argument to specify the name of the key file to generate.
* **--master-password**, **-mp**: argument to provide the master password.
* **--database**, **-d**: argument to specify the name of the database file. If the database does not exist, it gets created the first time the script is executed with an action other than GenerateKey.
* **--mode**, **-m**: cipher block mode of operation. Supported modes are ECB, CBC, and CTR. The mode used to check an entry or get the password of a specific user has to be the same that it was used to insert that entry to the database. Other than that, different modes can be used to insert records for different users into the database.
* **--username**, **-u**: the username to add.
* **--password**, **-p**: the password for the username provided.

The command to add an entry to the database looks like this:
`$ ./pwd-manager.py -a GetPassword -k <path to key file> -mp <master password> -d <path to database file> -m <mode> -u <username>`

## References
[1] Announcing the ADVANCED ENCRYPTION STANDARD (AES) [Online]. Available: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

[2] B. Kaliski, “PKCS #5: Password-Based Cryptography Specification Version 2.0,” RFC 2898, September 2000.

[3] Cryptography in Python with PyCrypto [Online]. Available: https://mborgerson.com/cryptography-in-python-with-pycrypto

[4] GitHub. AES256 with PKCS5 padding [Online]. Available: https://gist.github.com/pfote/5099161

[5] J. Katz and Y.Lindell, Introduction to Modern Cryptography: Principles and Protocols, Chapman & Hall/CRC Press, August 2007.

[6] LastPass [Online]. Available: https://lastpass.com/how-it-works/

[7] NIST Special Publication 800-132. Recommendation for Password-Based Key Derivation Part 1: Storage Applications [Online]. Available: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf

[8] Password Storage Cheat Sheet [Online]. Available: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet

[9] Python 2.7.11 Documentation: argparse [Online]. Available: https://docs.python.org/2/library/argparse.html

[10] Python 2.7.11 Documentation: Errors and Exceptions [Online]. Available: https://docs.python.org/2/tutorial/errors.html

[11] Python 2.7.11 Documentation: sqlite3 [Online]. Available: https://docs.python.org/2/library/sqlite3.html

[12] Python Cryptography Toolkit [Online]. Available: https://www.dlitz.net/software/pycrypto/doc/

[13] The Keyed-Hash Message Authentication Code (HMAC) [Online]. Available: http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

[14] Sebastian Raschka. A thorough guide to SQLite database operations in Python [Online]. Available: http://sebastianraschka.com/Articles/2014_sqlite_in_python_tutorial.html

[15] SQLite Python tutorial [Online]. Available: http://zetcode.com/db/sqlitepythontutorial/

[16] Using Padding in Encryption [Online]. Available: http://www.di-mgt.com.au/cryptopad.html

[17] Why shadow your passwd file? [Online]. Available: http://www.tldp.org/HOWTO/Shadow-Password-HOWTO-2.html

[18] Wikipedia. Block cipher mode of operation [Online]. Available: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
