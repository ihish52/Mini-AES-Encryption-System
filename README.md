# Mini-AES Encryption/Decryption Implementation
An interactive Mini-AES encryption/decryption system coded in basic Python, that takes in a plaintext message and outputs the encrypted binary message.

#### GitHub Repository location:
- https://github.com/ihish52/Mini-AES-Encryption-System

#### Referenced Mini-AES Paper:
- Mini Advanced Encryption Standard (Mini-AES): A Testbed for Cryptanalysis Students 
    - https://www.tandfonline.com/doi/abs/10.1080/0161-110291890948

### Requirements:
- Python 3.0 or later
- Uses standard Python functions with no extra downloaded packages.

# Running the Code:
### Encryption
Key can be viewed/changed by editing the 16-bit binary variable 'k' in encryption.py.
- Run file encryption.py.
- Enter plaintext message to encrypt.
- View binary of plaintext message.
- View binary of encrypted message.

### Decryption
Key can be viewed/changed by editing the 16-bit binary variable 'k' in decryption.py.
- Run file decryption.py.
- Enter binary of encrypted message copied from output of encryption.py.
- View decrypted binary of plaintext message (can be compared to output of encryption.py).
- View decrypted plaintext message string (compare to original string input to encryption.py).
