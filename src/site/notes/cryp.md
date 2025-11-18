---
{"dg-publish":true,"permalink":"/cryp/","noteIcon":""}
---



---

# #️⃣ **1. Caesar Cipher – Encryption & Decryption**

## **✔️ Main Code (Python)**

```python
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)

message = "HELLO WORLD"
shift = 3

encrypted = caesar_encrypt(message, shift)
decrypted = caesar_decrypt(encrypted, shift)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
```

---

## ⭐ **Variation – Caesar Cipher (User Input Version)**

```python
text = input("Enter message: ")
shift = int(input("Shift value: "))

enc = caesar_encrypt(text, shift)
dec = caesar_decrypt(enc, shift)

print("Encrypted:", enc)
print("Decrypted:", dec)
```

---

# #️⃣ **2. Playfair Cipher – Encryption Only**

## ✔️ **Main Code**

```python
def generate_matrix(key):
    key = key.lower().replace("j", "i")
    matrix = []
    used = set()

    for ch in key + "abcdefghijklmnopqrstuvwxyz":
        if ch not in used and ch != "j":
            used.add(ch)
            matrix.append(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j

def playfair_encrypt(message, key):
    message = message.lower().replace("j", "i").replace(" ", "")
    matrix = generate_matrix(key)

    i = 0
    prepared = []
    while i < len(message):
        a = message[i]
        b = message[i+1] if i+1 < len(message) else 'x'

        if a == b:
            b = 'x'
            i += 1
        else:
            i += 2

        prepared.append((a, b))

    encrypted = ""
    for a, b in prepared:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            encrypted += matrix[r1][(c1+1) % 5]
            encrypted += matrix[r2][(c2+1) % 5]
        elif c1 == c2:
            encrypted += matrix[(r1+1) % 5][c1]
            encrypted += matrix[(r2+1) % 5][c2]
        else:
            encrypted += matrix[r1][c2]
            encrypted += matrix[r2][c1]

    return encrypted

print(playfair_encrypt("HELLO", "MONARCHY"))
```

---

## ⭐ **Variation – Show 5×5 Matrix**

```python
matrix = generate_matrix("MONARCHY")
for row in matrix:
    print(row)
```

---

# #️⃣ **3. Vigenère Cipher – Encryption + Decryption**

## ✔️ **Main Code**

```python
def vigenere_encrypt(text, key):
    encrypted = ""
    key = key.lower()
    j = 0

    for ch in text:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            encrypted += chr((ord(ch)-base+shift)%26+base)
            j += 1
        else:
            encrypted += ch
    return encrypted

def vigenere_decrypt(cipher, key):
    decrypted = ""
    key = key.lower()
    j = 0

    for ch in cipher:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            decrypted += chr((ord(ch)-base-shift)%26+base)
            j += 1
        else:
            decrypted += ch
    return decrypted

msg = "ATTACK AT DAWN"
key = "LEMON"

cipher = vigenere_encrypt(msg, key)
plain = vigenere_decrypt(cipher, key)

print(cipher)
print(plain)
```

---

## ⭐ **Variation – Auto-Repeat Key**

```python
def repeat_key(text, key):
    key = key.lower()
    return ''.join(key[i % len(key)] for i in range(len(text)))

print(repeat_key("ATTACKATDAWN", "LEMON"))
```

---

# #️⃣ **4. Rail Fence Cipher – 3 Rails**

## ✔️ **Main Code**

```python
def rail_fence_encrypt(text, rails=3):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for ch in text:
        fence[rail].append(ch)
        rail += direction
        if rail == 0 or rail == rails-1:
            direction *= -1

    return ''.join(''.join(row) for row in fence)

print(rail_fence_encrypt("WEAREDISCOVERED"))
```

---

## ⭐ **Variation – Decrypt 3-Rail Cipher**

```python
def rail_fence_decrypt(cipher, rails=3):
    pattern = list(range(rails)) + list(range(rails-2,0,-1))
    length = len(cipher)

    fence = [[] for _ in range(rails)]
    index = 0

    for r in range(rails):
        for i in range(length):
            if pattern[i % len(pattern)] == r:
                fence[r].append(cipher[index])
                index += 1

    result = []
    rail_ptr = [0]*rails

    for i in range(length):
        r = pattern[i % len(pattern)]
        result.append(fence[r][rail_ptr[r]])
        rail_ptr[r] += 1

    return ''.join(result)

print(rail_fence_decrypt("WAEICVERDREEDSO"))
```

---

# #️⃣ **5. RSA Algorithm – Encryption & Decryption**

## ✔️ **Main Code**

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
public_key = key.publickey()

cipher = PKCS1_OAEP.new(public_key)
decipher = PKCS1_OAEP.new(key)

message = b"Hello RSA"

encrypted = cipher.encrypt(message)
decrypted = decipher.decrypt(encrypted)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
```

---

## ⭐ **Variation – Export Keys**

```python
private_pem = key.export_key()
public_pem = public_key.export_key()

print(private_pem.decode())
print(public_pem.decode())
```

---

# #️⃣ **6. SHA-1 and MD5 Hashing**

## ✔️ **Main Code**

```python
import hashlib

text = "hello world".encode()

print("MD5 :", hashlib.md5(text).hexdigest())
print("SHA-1 :", hashlib.sha1(text).hexdigest())
```

---

## ⭐ **Variation – SHA-256**

```python
print("SHA-256:", hashlib.sha256(text).hexdigest())
```

---

# #️⃣ **7. Digital Signature (RSA + SHA256)**

## ✔️ **Main Code**

```python
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
public_key = key.publickey()

message = b"Authorized document"
h = SHA256.new(message)

signature = pkcs1_15.new(key).sign(h)
print("Signature:", signature)

try:
    pkcs1_15.new(public_key).verify(h, signature)
    print("Signature Verified")
except:
    print("Verification Failed")
```

---

## ⭐ **Variation – Tamper Detection**

```python
fake_hash = SHA256.new(b"Modified document")

try:
    pkcs1_15.new(public_key).verify(fake_hash, signature)
    print("Signature Verified (Unexpected!)")
except:
    print("Tampered Document – Verification Failed")
```


---

## ✅ **1. Caesar Cipher – Encryption & Decryption**

**QUESTION:**  
Write a Python program to encrypt and decrypt a message using the Caesar Cipher with a given shift value.

### ✔️ **ANSWER (Python Code)**

```python
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)

message = "HELLO WORLD"
shift = 3

encrypted = caesar_encrypt(message, shift)
decrypted = caesar_decrypt(encrypted, shift)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
```

---

## ✅ **2. Playfair Cipher – Implement Encryption Only**

**QUESTION:**  
Implement the Playfair Cipher encryption using a 5×5 key matrix.

### ✔️ **ANSWER (Python Code)**

```python
def generate_matrix(key):
    key = key.lower().replace("j", "i")
    matrix = []
    used = set()

    for ch in key + "abcdefghijklmnopqrstuvwxyz":
        if ch not in used and ch != "j":
            used.add(ch)
            matrix.append(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j

def playfair_encrypt(message, key):
    message = message.lower().replace("j", "i").replace(" ", "")
    matrix = generate_matrix(key)

    # prepare digraphs
    i = 0
    prepared = []
    while i < len(message):
        a = message[i]
        b = message[i+1] if i+1 < len(message) else 'x'

        if a == b:
            b = 'x'
            i += 1
        else:
            i += 2

        prepared.append((a, b))

    # encrypt
    encrypted = ""
    for a, b in prepared:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            encrypted += matrix[r1][(c1+1) % 5]
            encrypted += matrix[r2][(c2+1) % 5]
        elif c1 == c2:
            encrypted += matrix[(r1+1) % 5][c1]
            encrypted += matrix[(r2+1) % 5][c2]
        else:
            encrypted += matrix[r1][c2]
            encrypted += matrix[r2][c1]

    return encrypted

print(playfair_encrypt("HELLO", "MONARCHY"))
```

---

## ✅ **3. Vigenère Cipher – Encryption & Decryption**

**QUESTION:**  
Write Python code to implement the Vigenère cipher.

### ✔️ **ANSWER**

```python
def vigenere_encrypt(text, key):
    encrypted = ""
    key = key.lower()
    j = 0

    for ch in text:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            encrypted += chr((ord(ch) - base + shift) % 26 + base)
            j += 1
        else:
            encrypted += ch
    return encrypted

def vigenere_decrypt(cipher, key):
    decrypted = ""
    key = key.lower()
    j = 0

    for ch in cipher:
        if ch.isalpha():
            shift = ord(key[j % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            decrypted += chr((ord(ch) - base - shift) % 26 + base)
            j += 1
        else:
            decrypted += ch
    return decrypted

msg = "ATTACK AT DAWN"
key = "LEMON"

cipher = vigenere_encrypt(msg, key)
plain = vigenere_decrypt(cipher, key)

print("Encrypted:", cipher)
print("Decrypted:", plain)
```

---

## ✅ **4. Rail Fence Cipher – 3 Rails**

**QUESTION:**  
Implement Rail-Fence cipher (3 rails) encryption and decryption.

### ✔️ **ANSWER**

```python
def rail_fence_encrypt(text, rails=3):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for ch in text:
        fence[rail].append(ch)
        rail += direction
        if rail == 0 or rail == rails-1:
            direction *= -1

    return ''.join(''.join(row) for row in fence)

print(rail_fence_encrypt("WEAREDISCOVERED"))
```

---

## ✅ **5. RSA Algorithm – Key Generation, Encryption & Decryption**

**QUESTION:**  
Write Python code to perform RSA key generation, encryption & decryption.

### ✔️ **ANSWER**

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# generate keys
key = RSA.generate(2048)
public_key = key.publickey()

cipher = PKCS1_OAEP.new(public_key)
decipher = PKCS1_OAEP.new(key)

message = b"Hello RSA"

encrypted = cipher.encrypt(message)
decrypted = decipher.decrypt(encrypted)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
```

**Install dependency:**

```
pip install pycryptodome
```

---

## ✅ **6. SHA-1 and MD5 Hashing**

**QUESTION:**  
Write Python code to generate MD5 and SHA-1 hashes.

### ✔️ **ANSWER**

```python
import hashlib

text = "hello world".encode()

md5_hash = hashlib.md5(text).hexdigest()
sha1_hash = hashlib.sha1(text).hexdigest()

print("MD5 :", md5_hash)
print("SHA-1 :", sha1_hash)
```

---

## ✅ **7. Simulation: Digital Signature (Signing + Verification)**

**QUESTION:**  
Use RSA + SHA-256 to generate a digital signature and verify it.

### ✔️ **ANSWER**

```python
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
public_key = key.publickey()

message = b"Authorized document"
h = SHA256.new(message)

signature = pkcs1_15.new(key).sign(h)
print("Signature:", signature)

# Verify
try:
    pkcs1_15.new(public_key).verify(h, signature)
    print("Signature Verified")
except:
    print("Verification Failed")
```

---

