import string
import secrets
import getpass
from config.config_vault import *
from .user_input import *
from .password_utils import *


def random_password(length: int = PASS_DEFAULTS["length"],
    min_upper: int = PASS_DEFAULTS["min_upper"],
    min_lower: int = PASS_DEFAULTS["min_lower"],
    min_nums: int = PASS_DEFAULTS["min_digits"],
    min_syms: int = PASS_DEFAULTS["min_symbols"], 
    avoid_ambig = PASS_DEFAULTS["avoid_ambiguous"]) -> str:
    """
    Generate a strong, cryptographically secure random password.

    The generated password enforces minimum character-class requirements
    and optionally excludes visually ambiguous characters. Randomness is
    provided by the `secrets` module.

    Args:
        length: Total length of the generated password.
        min_upper: Minimum number of uppercase letters.
        min_lower: Minimum number of lowercase letters.
        min_nums: Minimum number of digits.
        min_syms: Minimum number of symbols.
        avoid_ambig: If True, excludes visually ambiguous characters
            (e.g., l, I, 1, O, 0).

    Returns:
        A randomly generated password meeting all complexity requirements.

    Raises:
        ValueError: If the requested length is insufficient to satisfy
            the minimum character requirements.

    Security Notes:
        - Uses cryptographically secure randomness.
        - Enforces character-class minimums.
        - Optionally excludes ambiguous characters.
        - Limits excessive consecutive identical characters.
    """
    if length < (min_upper + min_lower + min_nums + min_syms):
        raise ValueError(
        f"Password length {length} is too short!\n"
        f"  Need at least {min_upper + min_lower + min_nums + min_syms} characters "
        f"for your requirements:\n"
        f"  • {min_upper} uppercase\n"
        f"  • {min_lower} lowercase\n"
        f"  • {min_nums} numbers\n"
        f"  • {min_syms} symbols"
    )

    # Define character pools
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    nums  = string.digits
    syms  = PASS_DEFAULTS["symbols_pool"]

    # Remove ambiguous chars
    if avoid_ambig:
        exclude = PASS_DEFAULTS["ambiguous_chars"]
        lower = ''.join(c for c in lower if c not in exclude)
        upper = ''.join(c for c in upper if c not in exclude)
        nums  = ''.join(c for c in nums  if c not in exclude)

    all_chars = lower + upper + nums + syms

    # Step 1: Guarantee minimums
    password = []
    password.extend(secrets.choice(upper) for _ in range(min_upper))
    password.extend(secrets.choice(lower) for _ in range(min_lower))
    password.extend(secrets.choice(nums)  for _ in range(min_nums))
    password.extend(secrets.choice(syms)  for _ in range(min_syms))

    # Step 2: Fill the rest randomly
    remaining = length - len(password)
    password.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Step 3: Shuffle all the characters 
    secrets.SystemRandom().shuffle(password)
    pw = ''.join(password)

    # Step 4: Ensure no excessive consecutive identical chars, reshuffle if needed
    max_shuffles = 1000
    shuffle_count = 0
    while max_consecutive_chars(pw) > PASS_DEFAULTS["max_consecutive"]:
        secrets.SystemRandom().shuffle(password)
        pw = ''.join(password)
        shuffle_count += 1
        if shuffle_count >= max_shuffles:
            break

    return pw

def ask_password(prompt: str = "Password:") -> str | None:
    """
    Prompt the user to enter or generate a password.

    The user may manually enter a password or choose to generate a
    random password using default or customized parameters. The
    prompt loops until a valid password is accepted or the user quits.

    Args:
        prompt: Prompt displayed to the user.

    Returns:
        The accepted password string, or None if the user chooses to quit.

    Side Effects:
        Prompts for user input.
        Prints password generation options and feedback.
    """
    while True:
        print(f"\n{prompt}:")
        print(f"  • Type 'g' → generate strong {PASS_DEFAULTS["length"]}-char password")
        print("  • Type 'c' → generate customizable random password")
        print("  • Type 'q' → quit")
        print("  • Press Enter to type your own")
        choice = input(" → ").strip().lower()

        if choice == "":
            pw = getpass.getpass(
                f"Enter password (min length = {PASS_DEFAULTS['min_length']}): "
                ).strip()
            if len(pw) < PASS_DEFAULTS["min_length"]:
                print(f"  Password too short (minimum {PASS_DEFAULTS['min_length']} characters)")
                continue
            return pw

        elif choice == "g":
            pw = random_password()
            print(f" Generated: {pw}")
            if input("\n Accept this password? (y/n): ").strip().lower() != "y":
                continue
            return pw

        elif choice == "c":
            pw_len = get_int(
                f"\n  Enter desired length (minimum {PASS_DEFAULTS['min_length']}, "
                f"Enter for default of {PASS_DEFAULTS['length']}): ", 
                default=PASS_DEFAULTS["length"]
                )
            if pw_len is None:
                break
            if pw_len < PASS_DEFAULTS['min_length']:
                print(f"  Length too short, using {PASS_DEFAULTS['length']}.")
                pw_len = PASS_DEFAULTS['length']

            min_upper = get_int("  Minimum upper case (Enter for default): ", 
                                default=PASS_DEFAULTS["min_upper"])
            if min_upper is None:
                break
            min_nums = get_int("  Minimum numbers (Enter for default): ", 
                               default=PASS_DEFAULTS["min_digits"])
            if min_nums is None:
                break
            min_syms = get_int("  Minimum symbols (Enter for default): ", 
                               default=PASS_DEFAULTS["min_symbols"])
            if min_syms is None:
                break
            try:
                pw = random_password(length = pw_len,
                                      min_upper = min_upper,
                                        min_nums = min_nums,
                                          min_syms = min_syms)
            except ValueError as e:
                print (f"\n  {e}")
                continue

            print(f"\n Generated: {pw}")
            if input("\n Accept this password? (y/n): ").strip().lower() != "y":
                continue
            return pw
        elif choice == "q":
            return None
        else:
            print("Invalid — press Enter, 'g', or 'c'")


def max_consecutive_chars(pw: str) -> int:
    """
    Determine the longest run of identical consecutive characters.

    Args:
        pw: Password string to analyze.

    Returns:
        Length of the longest sequence of identical consecutive characters.
    """
    max_run = 1
    current_run = 1
    
    for a, b in zip(pw, pw[1:]):
        if a == b:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    
    return max_run