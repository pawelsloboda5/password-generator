# secure_auth.py
"""Secure Password Generation & MFA Assignment
Enhanced with granular feedback, dual recommendations, and OTP‑based MFA.
"""

import secrets
import string
import re
from datetime import datetime, timedelta
from typing import Tuple, Optional, List

LOWER, UPPER = string.ascii_lowercase, string.ascii_uppercase
DIGITS, SYMBOLS = string.digits, string.punctuation

# ---------------------- Password Generation ---------------------- #

def generate_password(length: int = 12,
                      require: Optional[List[str]] = None) -> str:
    if length < 12:
        raise ValueError("Password length must be at least 12 characters.")
    pools = {"lower": LOWER, "upper": UPPER, "digit": DIGITS, "symbol": SYMBOLS}
    require = require or list(pools.keys())
    mandatory = [secrets.choice(pools[k]) for k in require]
    remaining = length - len(mandatory)
    all_chars = "".join(pools.values())
    password_chars = mandatory + [secrets.choice(all_chars) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

# ---------------------- Password Verification ------------------- #

strength_re = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':\",.<>/?]).{12,}$"
)


def _missing_components(pw: str):
    missing = []
    if not re.search(r"[a-z]", pw):
        missing.append("lowercase letter")
    if not re.search(r"[A-Z]", pw):
        missing.append("uppercase letter")
    if not re.search(r"\d", pw):
        missing.append("digit")
    if not re.search(r"[!@#$%^&*()_+\-=[\]{};':\",.<>/?]", pw):
        missing.append("symbol")
    extra_len = max(0, 12 - len(pw))
    return missing, extra_len


def suggest_passwords(pw: str) -> Tuple[str, str]:
    """Return (rec1, rec2). rec1 keeps original prefix, rec2 shuffled."""
    missing, extra = _missing_components(pw)
    pools = {
        "lowercase letter": LOWER,
        "uppercase letter": UPPER,
        "digit": DIGITS,
        "symbol": SYMBOLS,
    }
    additions = [secrets.choice(pools[m]) for m in missing]
    if extra:
        all_chars = "".join(pools.values())
        additions.extend(secrets.choice(all_chars) for _ in range(extra))
    # Recommendation 1: append additions to original
    rec1 = pw + "".join(additions)
    # Recommendation 2: shuffle everything
    rec2_chars = list(pw + "".join(additions))
    secrets.SystemRandom().shuffle(rec2_chars)
    rec2 = "".join(rec2_chars)
    return rec1, rec2


def check_password_strength(password: str) -> Tuple[str, str, Optional[Tuple[str, str]]]:
    if not password:
        return "invalid", "Password cannot be empty.", None

    if strength_re.match(password):
        return "strong", "Excellent! Your password meets all best‑practice criteria.", None

    missing, extra_len = _missing_components(password)
    parts = []
    if missing:
        parts.append("Add " + ", ".join(missing))
    if extra_len:
        parts.append(f"increase length by {extra_len} more characters")
    feedback = "Weak password — " + "; and ".join(parts) + "."
    recs = suggest_passwords(password)
    return "weak", feedback, recs

# ---------------------- MFA with One‑Time Password -------------- #

def mfa_login(valid_window: int = 60) -> bool:
    otp_code = f"{secrets.randbelow(1_000_000):06d}"
    expiry = datetime.now() + timedelta(seconds=valid_window)
    print(f"\n[OTP] Your one‑time code is: {otp_code} (valid {valid_window}s)\n")
    try:
        entered = input("Enter the OTP: ").strip()
    except KeyboardInterrupt:
        print("\nMFA cancelled.")
        return False
    if datetime.now() > expiry:
        print("OTP expired.")
        return False
    if entered == otp_code:
        print("OTP verified — login successful!")
        return True
    print("Incorrect OTP — authentication failed.")
    return False

# ---------------------- CLI Menu -------------------------------- #

def prompt_int(msg: str, default: Optional[int] = None) -> Optional[int]:
    raw = input(msg).strip()
    if not raw and default is not None:
        return default
    if raw.isdigit():
        return int(raw)
    return None


def main() -> None:
    last_generated: Optional[str] = None

    menu = """
================ Secure Auth Utility ================
1) Generate a secure password
2) Check password strength
3) Simulate MFA login (OTP)
4) Exit
Choose an option (1‑4): """

    while True:
        try:
            choice = input(menu).strip()
        except KeyboardInterrupt:
            print("\nProgram terminated.")
            break

        if choice == "1":
            length = prompt_int("\nEnter desired password length (>=12, Enter for 12): ", default=12)
            if length is None:
                print("Please enter a number or press Enter.\n")
                continue
            try:
                pwd = generate_password(length)
                last_generated = pwd
                print(f"Generated password: {pwd}\n")
            except ValueError as err:
                print(f"Error: {err}\n")

        elif choice == "2":
            if last_generated:
                candidate = input("\nPress Enter to evaluate last generated password, or type a different one: ")
                password = last_generated if candidate == "" else candidate
            else:
                password = input("\nEnter password to check: ")

            rating, msg, recs = check_password_strength(password)
            print(f"Strength: {rating.upper()} — {msg}")
            if recs:
                rec1, rec2 = recs
                print("Recommended upgrade 1 (keep prefix):", rec1)
                print("Recommended upgrade 2 (shuffled):    ", rec2)
            print()

        elif choice == "3":
            mfa_login()
            print()

        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option.\n")

if __name__ == "__main__":
    main()
