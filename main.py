import secrets
import string
import argparse
import hashlib

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: 'requests' not installed. Pwned check disabled. Install with: pip install requests")

def generate_password(length: int = 12,
                      use_upper: bool = True,
                      use_lower: bool = True,
                      use_digits: bool = True,
                      use_special: bool = True) -> str:
    """
    Generate a secure random password.
    """
    chars = ""
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
    
    if not chars:
        raise ValueError("At least one character type must be selected")
    
    return ''.join(secrets.choice(chars) for _ in range(length))

def password_strength(password: str) -> str:
    """
    Evaluate password strength: Weak / Medium / Strong.
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~" for c in password):
        score += 1
    
    if score <= 3:
        return "Weak"
    elif score <= 5:
        return "Medium"
    else:
        return "Strong"

def is_pwned(password: str) -> bool:
    """
    Check if password has been pwned using HIBP API (k-anonymity).
    Returns True if pwned, False otherwise (or if check fails).
    """
    if not REQUESTS_AVAILABLE:
        return False
    
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.split(':')[0] == suffix:
                    return True
    except Exception:
        # Network error or API issue – assume not pwned to avoid blocking
        pass
    return False

def main():
    parser = argparse.ArgumentParser(description="Password Generator & Strength Checker + Pwned Check")
    parser.add_argument("-l", "--length", type=int, default=12,
                        help="Password length (default: 12)")
    parser.add_argument("--no-upper", action="store_true",
                        help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true",
                        help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true",
                        help="Exclude digits")
    parser.add_argument("--no-special", action="store_true",
                        help="Exclude special characters")
    parser.add_argument("-c", "--check", metavar="PASSWORD",
                        help="Check strength and pwned status of the given password")
    parser.add_argument("--pwned", action="store_true",
                        help="Also check if generated/checked password is pwned (requires internet)")
    
    args = parser.parse_args()

    # Check mode
    if args.check:
        pwd = args.check
        print(f"Password: {pwd}")
        print(f"Strength: {password_strength(pwd)}")
        if args.pwned:
            if is_pwned(pwd):
                print("PWNED: This password has appeared in data breaches! Do not use it.")
            else:
                print("Not pwned: No known breaches for this password.")
        return

    # Generation mode
    try:
        pwd = generate_password(
            length=args.length,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
            use_special=not args.no_special
        )
        print(f"Generated password: {pwd}")
        print(f"Strength: {password_strength(pwd)}")
        
        if args.pwned:
            if is_pwned(pwd):
                print("PWNED: This generated password is compromised! Generate another one.")
            else:
                print("Not pwned: Safe to use.")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()