# Password Tool – Generator + Strength Checker + Pwned Lookup

A secure, CLI‑based password utility written in Python. It generates cryptographically strong passwords, evaluates their strength, and checks if they have appeared in known data breaches using the **Have I Been Pwned (HIBP) API** (k‑anonymity model – your password never leaves your machine).

## Features

- **Random password generation** – customizable length and character sets (uppercase, lowercase, digits, specials)
- **Strength evaluation** – Weak / Medium / Strong based on length and character variety
- **Pwned password check** – queries HIBP API (optional, requires `requests`)
- **Secure randomness** – uses Python’s `secrets` module, not `random`
- **No external dependencies** – pwned check works with optional `requests` only

## Requirements
- **Python 3.6+**
- **[OPTIONAL] request (for pwned check)**

## Installation

```bash
# Clone the repository
git clone https://github.com/ha1ron23/password-generator.git
cd password-tool

# (Optional) Install requests for pwned check
pip install requests
```

## Usage
Run the script from the terminal:
```bash
python main.py [options]
```
### Generate a password
```bash
# Default: 12 characters, all character types
python main.py

# 20 characters, no special symbols
python main.py -l 20 --no-special

# Only lowercase + digits
python main.py --no-upper --no-special
```
### Check strength of an existing password
```bash
python main.py -c "mypassword123"
```
### Check strength + pwned status
```bash
python main.py -l 16 --pwned
```

## Command line options
**-l, --lenght  password length (12 by default)**
**--no-upper  exclude uppercase letters**
**--no-lower	exclude lowercase letters**
**--no-digits	exclude digits**
**--no-special	exclude special characters !@#$%^&*()-_=+[]{}|;:,.<>?/~**
**-c, --check	check strength (and pwned if --pwned) of the given password**
**--pwned	Enable Have I Been Pwned check (requires internet)**

## How the pwned check works
The tool never sends your actual password over the network. It follows the **k‑anonymity** model:

  1. Computes **SHA‑1** hash of the password.

  2. Sends only the first 5 characters of the hash to **HIBP**.

  3. Receives a list of **hash suffixes** that match the **prefix**.

  4. Checks locally if your full **hash** appears in the list.

This way **your password** stays private!

## Development
Want to contribute? Ideas for improvement:

  - Export generated passwords to a file (encrypted)

    Batch check multiple passwords from a list

    Add entropy calculation

## License
MIT License – free to use and modify.
