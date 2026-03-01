import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


ENCRYPTED_DS  = "OSnaALIWUkpOziVAMycaZQ=="   
TARGET        = "master_on"                   
ALGORITHM     = "AES"                         
MAX_RANGE     = 1000                     



def generate_key(static_key: int) -> bytes:
  
    key_bytes      = bytearray(16)
    static_key_b   = str(static_key).encode("utf-8")
    length         = min(len(static_key_b), 16)
    key_bytes[:length] = static_key_b[:length]
    return bytes(key_bytes)


def try_decrypt(encrypted: bytes, key_int: int) -> str | None:
   
    try:
        key     = generate_key(key_int)
        cipher  = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        dec     = cipher.decryptor()
        raw     = dec.update(encrypted) + dec.finalize()

        # Remove PKCS5 padding
        pad_len = raw[-1]
        if pad_len < 1 or pad_len > 16:
            return None
        return raw[:-pad_len].decode("utf-8")
    except Exception:
        return None


def crack(encrypted_b64: str, target: str, max_range: int) -> int | None:
    encrypted = base64.b64decode(encrypted_b64)

    print(f"[*] Encrypted string : {encrypted_b64}")
    print(f"[*] Target plaintext : {target}")
    print(f"[*] Brute forcing    : 0 → {max_range:,}")
    print(f"[*] Algorithm        : AES/ECB/PKCS5Padding\n")

    for i in range(max_range + 1):
        if i % 100_000 == 0 and i > 0:
            print(f"    ... tried {i:,} keys so far")

        result = try_decrypt(encrypted, i)
        if result == target:
            return i

    return None


def main():
    found = crack(ENCRYPTED_DS, TARGET, MAX_RANGE)

    print()
    if found is not None:
        print(f"[+] PIN FOUND: {found}")
    else:
        print(f"[-] PIN not found in range 0–{MAX_RANGE:,}")


if __name__ == "__main__":
    main()
