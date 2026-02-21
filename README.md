---
<img width="1536" height="1024" alt="Image" src="https://github.com/user-attachments/assets/e076b51d-616d-48de-8280-b75f8adc3e44" />
🔥 Linux Privilege Escalation Lab

Complete Vulnerable Environment for Hands‑On Practice

> ⚠️ **WARNING:** This lab is strictly for authorized penetration testing and educational purposes only. Do NOT deploy on production systems.

---

📌 Overview

This project provides a **fully automated vulnerable Linux environment** designed for practicing:

* Linux Privilege Escalation
* SUID Exploitation
* Kernel Exploits
* Cron Job Abuse
* NFS Misconfigurations
* Credential Harvesting
* Sudo Escapes
* Environment Variable Exploits

The lab simulates real-world misconfigurations commonly found during internal penetration tests and OSCP-style exams.

---

🎯 Lab Features

The setup script automatically configures:

* 🔓 Vulnerable kernel simulation (Dirty COW scenario)
* 📦 Exim RCE misconfiguration
* 🧠 Memory credential leakage
* 📁 Config file password exposure
* 📜 Bash history credential leakage
* 🧰 Dangerous sudo misconfigurations
* 🌐 NFS `no_root_squash` vulnerability
* ⏰ Insecure cron jobs
* 🔗 SUID shared object injection
* 🔄 Environment variable exploitation
* 🗂 Nginx symlink attack simulation

---

🏗 Lab Architecture

Default Setup

| Component       | Value              |
| --------------- | ------------------ |
| Lab Directory   | `/opt/privesc-lab` |
| User            | `user`             |
| Password        | `password123`      |
| Tools Directory | `/home/user/tools` |

---

🧪 Exercises Included

1️⃣ Kernel Exploitation

Simulated **Dirty COW (CVE-2016-5195)** vulnerability
Includes:

* linux-exploit-suggester
* Dirty COW PoC source code

---

2️⃣ Exim RCE Simulation

Simulated **CVE-2016-1531** Exim misconfiguration.

---

3️⃣ Memory Password Mining

Extract credentials from:

* `/etc/passwd`
* Active processes
* Temporary files

---

4️⃣ Configuration File Credential Discovery

Targets:

* OpenVPN config
* IRC config
* Plaintext auth files

---

5️⃣ Bash History Abuse

Search `.bash_history` for exposed credentials.

---

6️⃣–8️⃣ Sudo Exploitation

Misconfigured sudo rules for:

* `/bin/find`
* `/usr/bin/awk`
* `/usr/bin/nmap`
* `/usr/bin/vim`
* `/usr/sbin/apache2`

Test with:

```bash
sudo -l
```

---

9️⃣ NFS Privilege Escalation

`no_root_squash` misconfiguration in:

```
/etc/exports
```

---

🔟–1️⃣2️⃣ Cron Job Exploitation

Vulnerable cron jobs:

* Writable script execution
* Tar wildcard injection
* PATH abuse

---

1️⃣3️⃣ SUID Shared Object Injection

Vulnerable binary:

```
/usr/local/bin/suid-so
```

Loads malicious `.so` from user directory.

---

1️⃣4️⃣ Nginx Symlink Attack (Simulated)

---

1️⃣5️⃣–1️⃣6️⃣ SUID Environment Variable Exploits

Improper use of:

```
execve()
```

Allows environment manipulation.

---

🚀 Installation

```bash
chmod +x setup.sh
sudo ./setup.sh
```

Switch to the lab user:

```bash
su - user
```

---

🧪 Quick Verification

Check sudo privileges:

```bash
sudo -l
```

Check SUID binaries:

```bash
find / -perm -4000 2>/dev/null
```

---

🎓 Learning Objectives

After completing this lab, you will understand:

* How privilege escalation works in Linux
* How to enumerate misconfigurations effectively
* How kernel exploits are identified
* How cron jobs can be abused
* How SUID binaries can be weaponized
* How environment variables can lead to root access

---

📚 Recommended Practice Flow

1. Start as `user`
2. Perform full enumeration
3. Identify attack surface
4. Exploit one vulnerability at a time
5. Gain root
6. Document your methodology

---

⚠️ Legal Disclaimer

This project is intended for:

* Personal lab environments
* Cybersecurity training
* Authorized red team exercises
* Educational workshops

The author is not responsible for misuse.

---

👨‍💻 Author

**Rana Sen**
Cyber Security Researcher
Linux Privilege Escalation Enthusiast

---
