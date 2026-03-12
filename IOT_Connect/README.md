Step1: Analyze the Application Using JADX

The first step was to decompile the APK using JADX to inspect the source code.

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 24 15 in the evening" src="https://github.com/user-attachments/assets/d70db2f2-7c5d-4128-8d96-0bd1daea56e5" />

After loading the application into JADX, I navigated to the AndroidManifest.xml file to examine how the application components were configured.
During this review, I discovered the following configuration:

<img width="557" height="148" alt="Screenshot 2026-02-28 at 7 27 27 in the evening" src="https://github.com/user-attachments/assets/b0c1fab4-6850-494b-994f-2d0116658a80" />

Vulnerability
The MasterReceiver component is configured with:

```bash
android:exported="true"
```

However, it does not define any android:permission attribute.
This means that any external application or ADB command can send a broadcast to this receiver, allowing unauthorized users to trigger internal functionality.
This is a common Android security issue known as an:
Exported BroadcastReceiver Vulnerability

Step2: Analyze MasterSwitchActivity

Next, I examined the logic inside MasterSwitchActivity.java to understand how the master control system works.

<img width="854" height="441" alt="Screenshot 2026-02-28 at 7 39 06 in the evening" src="https://github.com/user-attachments/assets/2d05de78-05d2-4153-afe0-0906e84bbc6b" />

From the code, I observed that the application checks whether the user is a Guest. Guest users are restricted from controlling the master switch through the user interface.
However, this validation only exists in the UI layer. If a broadcast is sent directly to the receiver, the UI restrictions can be bypassed.
The application expects a broadcast with:

```bash
Action: MASTER_ON
Extra: key (PIN)
```

The receiver then verifies the PIN before enabling the master switch.
Since we do not know the correct PIN, the next step is to analyze how it is verified.

Step3: Analyze the PIN Validation Logic

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 28 23 in the evening" src="https://github.com/user-attachments/assets/324f30aa-9969-4bcb-b109-db4358eedea4" />

And I see checker_key:

Searching the code for MASTER_ON revealed that the application uses a checker function to validate the PIN.

<img width="1470" height="956" alt="Screenshot 2026-02-28 at 7 29 58 in the evening" src="https://github.com/user-attachments/assets/e5b23d06-b073-4e13-8690-b27e6bf3e622" />

Inside the code, I discovered an encrypted string:

```bash
OSnaALIWUkpOziVAMycaZQ==
```

The application uses AES encryption to validate the PIN.
The key generation process works as follows:
The PIN is converted to a string.
The string is padded to 16 bytes.
The resulting value is used as the AES key.
The encrypted value is decrypted and compared to:
```bash
master_on
```

Weakness

Although AES is a strong encryption algorithm, the key space is extremely small because the key is derived from a numeric PIN.
The PIN range appears to be:
```bash
000 – 999
```

This makes the encryption vulnerable to brute force attacks

Step 4: Brute Force the PIN

To recover the correct PIN, I wrote a Python script to brute force the AES key by testing all possible PIN values.

My script save to solve.py, you can check it out.

And found the PIN:

<img width="578" height="382" alt="Screenshot 2026-02-28 at 7 43 38 in the evening" src="https://github.com/user-attachments/assets/9296b268-0358-41d9-a24e-a62741dd94d5" />

Step 5: Exploiting the Broadcast Receiver

Before sending the exploit, I first registered an account and logged into the application.
As expected, a Guest user cannot control the master switch through the UI, and all devices remain turned off.
However, since the BroadcastReceiver is exported, we can bypass the UI restriction and directly send a broadcast using ADB.


<img width="444" height="776" alt="Screenshot 2026-02-28 at 7 45 10 in the evening" src="https://github.com/user-attachments/assets/03a01e4f-62fb-4e6d-9633-3f319c3a9641" />

And you can see it all are turning off like the above that we anaylze Guest cannot control all the system:

<img width="439" height="780" alt="Screenshot 2026-02-28 at 7 46 22 in the evening" src="https://github.com/user-attachments/assets/b3ba268d-a6c3-4044-a103-057fce33c375" />

but we have a PIN so we control this via adb command:

Exploit Command
```bash
adb shell am broadcast -a MASTER_ON --ei key 345
```

This sends the MASTER_ON broadcast along with the correct PIN.

<img width="581" height="384" alt="Screenshot 2026-02-28 at 7 48 18 in the evening" src="https://github.com/user-attachments/assets/7fe48551-5c11-433c-88bd-dfcfc75f7005" />

Step 6: Result

After sending the broadcast, the application processes the request and enables the master switch.
All devices are successfully turned ON, demonstrating that the access control mechanism can be bypassed.
This confirms that the application is vulnerable to unauthorized broadcast injection.

<img width="442" height="795" alt="Screenshot 2026-02-28 at 7 49 27 in the evening" src="https://github.com/user-attachments/assets/539862cb-1f7a-4829-8762-2b72e947595a" />

<img width="452" height="781" alt="Screenshot 2026-02-28 at 7 50 12 in the evening" src="https://github.com/user-attachments/assets/b782e34e-8873-4bac-a7ef-6e4ed994d505" />











