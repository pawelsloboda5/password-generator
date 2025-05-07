# Secure Auth Utility

Github URL: https://github.com/pawelsloboda5/password-generator

A self‑contained Python CLI that lets users:

1. **Generate** cryptographically secure passwords
2. **Check** the strength of any password with granular guidance
3. **Simulate MFA** using a console‑displayed 6‑digit One‑Time Password (OTP)

No external libraries required—100 % standard library.

---

## 🗂️ File Layout

| File             | Purpose                                         |
| ---------------- | ----------------------------------------------- |
| `secure_auth.py` | Main application (password gen/verify, MFA CLI) |
| `README.md`      | This documentation                              |

---

## 🚀 Quick Start

```bash
python secure_auth.py
```

You’ll see:

```
================ Secure Auth Utility ================
1) Generate a secure password
2) Check password strength
3) Simulate MFA login (OTP)
4) Exit
Choose an option (1‑4):
```

### 1️⃣ Generate a Password

* Choose **1**
* Enter a length (≥ 12) or press **Enter** for default 12.

The password **always** contains at least one lowercase, uppercase, digit, and symbol.

### 2️⃣ Check Password Strength

* Choose **2**
* If you just generated a password, press **Enter** to reuse it, or type a different one.

Output shows:

* **Rating** (STRONG / WEAK)
* **Specific feedback** (missing categories, extra length needed)
* **Two upgrade suggestions**:

  1. Original prefix with required additions appended
  2. Same characters shuffled for extra entropy

### 3️⃣ MFA (OTP) Demo

* Choose **3**
* A 6‑digit code appears (simulating SMS/email)
* Enter the code within 60 s to succeed

---

## 🔒 Password Policy & Feedback Logic

| Criterion      | Requirement                                         |
| -------------- | --------------------------------------------------- |
| Length         | ≥ 12 characters                                     |
| Character sets | ≥ 1 lowercase, ≥ 1 uppercase, ≥ 1 digit, ≥ 1 symbol |

`secure_auth.py` inspects the supplied password with regex + incremental checks to determine what’s missing and how many extra characters are needed. It then constructs the two recommendations described above.

---

## 🛠️ Error Handling

* Non‑numeric length → graceful message, re‑prompt
* Ctrl‑C during any input → catches `KeyboardInterrupt` without crashing
* OTP timeout → clear expiry message
* Invalid OTP → authentication failed message without exiting program

---

## 📚 Functions Overview

| Function                             | Description                                            |
| ------------------------------------ | ------------------------------------------------------ |
| `generate_password(length, require)` | Returns secure random password meeting policy          |
| `check_password_strength(pw)`        | Returns rating, feedback, and two recommended upgrades |
| `suggest_passwords(pw)`              | Builds the two upgrade examples                        |
| `mfa_login(valid_window)`            | Handles OTP generation, expiry, verification           |
| `prompt_int(msg, default)`           | Safe numeric input helper                              |

---

## 🧪 Demo Script (for grading)

1. **Generate** a 16‑char password
2. **Check** weak password `Student123` → observe feedback & recommendations
3. **Check** generated password → STRONG
4. **Run** MFA, validate OTP, then rerun and let OTP expire for failure path
5. **Test** error cases: wrong menu choice, bad length, Ctrl‑C

---

## 🧑‍💻 Extending

* Swap OTP delivery for actual email/SMS by integrating `smtplib` or Twilio.
* Persist passwords in an encrypted vault (e.g., `cryptography` Fernet).
* Add diceware or passphrase mode in `generate_password`.

---

## 📄 License

under MIT Open-source License. Educational / assignment use only. Feel free to adapt.
