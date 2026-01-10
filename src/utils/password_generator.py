import string
import secrets
import getpass
from config.config_vault import PASS_DEFAULTS, UTF8, WORD_LIST
from .user_input import get_int
from utils.Entry import print_bytearray

LOWER = string.ascii_lowercase.encode("ascii")
UPPER = string.ascii_uppercase.encode("ascii")
NUMS  = string.digits.encode("ascii")
SYMBS = PASS_DEFAULTS["symbols_pool"].encode("ascii")
SAFE_SYMBS = PASS_DEFAULTS["safe_symbols"].encode("ascii")

# Used to filter out unwanted chars
AMBIG = set(PASS_DEFAULTS["ambiguous_chars"].encode("ascii"))
UNSAFE_SYMBS = set(b for b in SYMBS if b not in SAFE_SYMBS)

DEFAULT_MIN_FALLBACK = 3


class DicewarePassphrase:
    """
    Diceware wordlist loader and generator.
    """
    def __init__(self, path: str):
        """Load a Diceware wordlist.

        Args:
            path: Path to wordlist file.
        """
        self._words = self._load(path)

    def _load(self, path: str) -> dict[str, str]:
        """
        Load Diceware keys and words.

        Args:
            path: Wordlist file path.

        Returns:
            Mapping of dice keys to words.

        Raises:
            ValueError: If a key is invalid.
        """
        words = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                key, word = line.strip().split(maxsplit=1)
                if len(key) != 5 or not set(key) <= set("123456"):
                    raise ValueError(f"Invalid Diceware key: {key}")
                words[key] = word
        return words

    def get_word(self, key: str) -> bytearray:
        """Return a word for a dice key.

        Args:
            key: Five-digit Diceware key.

        Returns:
            Capitalized word as bytes.
        """
        return bytearray(self._words[key].encode(UTF8))

    def clear(self):
        """Clear loaded wordlist."""
        self._words.clear()

    def roll_5dice(self) -> str:
        """Roll five dice securely.

        Returns:
            Five-digit dice string.
        """
        return ''.join(str(randbelow_reject(6) + 1) for _ in range(5))


def filter_out_bytes(pool: bytes, exclude: set[int]) -> bytes:
    """
    Remove excluded bytes from a pool.

    Args:
        pool: Candidate bytes.
        exclude: Byte values to remove.

    Returns:
        Filtered bytes.
    """
    return bytes(b for b in pool if b not in exclude)

def randbelow_reject(n: int) -> int:
    """
    Returns a uniform random integer in [0, n) using rejection sampling.
    Removes modulo bias.

    Args:
        n: Upper bound (exclusive).

    Returns:
        Random integer.

    Raises:
        ValueError: If n <= 0.
    """
    if n <= 0:
        raise ValueError("n must be > 0")
    
    # Number of bits k needed to represent int n
    k = n.bit_length()

    # Bit mask. Bitwise leftshift
    mask = (1 << k) - 1

    while True:
        r = secrets.randbits(k) & mask
        # Only accept values below n
        if r < n:
            return r

def secure_shuffle(buf: bytearray) -> None:
    """
    Perform in place Fisher-Yates shuffle on the array.
    Same as secrets.shuffle but without modulo bias.

    Args:
        buf: Buffer to shuffle.
    """
    n = len(buf)
    for i in range(n - 1, 0, -1):
        j = randbelow_reject(i + 1)
        buf[i], buf[j] = buf[j], buf[i]

def random_password(
    length: int = PASS_DEFAULTS["length"],
    min_upper: int = PASS_DEFAULTS["min_upper"],
    min_lower: int = PASS_DEFAULTS["min_lower"],
    min_nums: int = PASS_DEFAULTS["min_digits"],
    min_symbs: int = PASS_DEFAULTS["min_symbols"], 
    avoid_ambig: bool = PASS_DEFAULTS["avoid_ambiguous"],
    use_safe_symbs: bool = PASS_DEFAULTS["use_safe_symbs"]) -> bytearray:
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
        use_safe_symbs: If True, only uses a set of bank safe symbols.

    Returns:
        A randomly generated password (bytearray)

    Security Notes:
        - Uses cryptographically secure randomness.
        - Limits excessive consecutive identical characters.
    """
    if length < (min_upper + min_lower + min_nums + min_symbs):
        raise ValueError(
        f"Password length {length} is too short!\n"
        f"  Need at least {min_upper + min_lower + min_nums + min_symbs} characters "
        f"for requirements:\n"
        f"  • {min_upper} uppercase\n"
        f"  • {min_lower} lowercase\n"
        f"  • {min_nums} numbers\n"
        f"  • {min_symbs} symbols"
    )
    # Define character pools
    lower = LOWER
    upper = UPPER
    nums  = NUMS
    symbs  = SYMBS

    # Filter out ambiguity and unsafe symbols 
    if avoid_ambig:
        lower = filter_out_bytes(lower, AMBIG)
        upper = filter_out_bytes(upper, AMBIG)
        nums  = filter_out_bytes(nums,  AMBIG)
    if use_safe_symbs:
        symbs = filter_out_bytes(symbs, UNSAFE_SYMBS)
    
    # Create a list of all possible chars for filling the remainder
    all_chars = bytearray(lower + upper + nums + symbs)
    secure_shuffle(all_chars)
    all_chars = bytes(all_chars)
    alnum = lower + upper + nums
    
    password = bytearray()

    # Guarantee minimums
    password.extend(secrets.choice(upper) for _ in range(min_upper))
    password.extend(secrets.choice(lower) for _ in range(min_lower))
    password.extend(secrets.choice(nums)  for _ in range(min_nums))
    password.extend(secrets.choice(symbs)  for _ in range(min_symbs))

    # Fill remaining
    remaining = length - len(password)
    password.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Shuffle
    for i in range(5):
        secure_shuffle(password)

    # Enforce max consecutive rule
    max_consecutive = PASS_DEFAULTS["max_consecutive"]
    max_shuffles = 10000

    for i in range(1, max_shuffles):
        # Ensure start and end are not symbols
        password[0] = secrets.choice(alnum)
        password[-1] = secrets.choice(alnum)

        if check_max_consecutive_bytes(password, max_consecutive):
            break
        secure_shuffle(password)

        # Increment max consecutive every x shuffles. 
        # Prevents infinite loop while keeping the max consecutive count low.
        # Only useful for extremely long passwords.
        if i % 1000 == 0:
            max_consecutive += 1

    return password

def ask_password(prompt: str = "Password:") -> bytearray | None:
    """
    Prompt the user to enter or generate a password.

    The user may manually enter a password or choose to generate a
    random password using default or customized parameters. The
    prompt loops until a valid password is accepted or the user quits.

    Args:
        prompt: Prompt displayed to the user.

    Returns:
        bytearray- the entered or generated password

        empty bytearray- user chose to delete the password

        None- user chose to quit
        
    Side Effects:
        Prompts for user input.
        Prints password generation options and feedback.
    """
    while True:
        print(f"\n{prompt}:")
        print(f"  • '1' → Generate password (i.e X[hX)CqYk878pkf$l)")
        print("  • '2' → Generate passphrase (i.e. correct-horse-battery-staple)")
        print("  • '3' → Type your own (i.e. SecretP433w0rd)")
        print("\n  • 'd' → Delete password")
        print("  • 'Enter' → Quit/Skip")
        
        choice = input(" → ").strip().lower()

        # Type your own
        if choice == "3":
            pw = bytearray(getpass.getpass(
                f"Type password (Min length = {PASS_DEFAULTS["min_custom_length"]}): "
                ).strip().encode(UTF8))
            if len(pw) < PASS_DEFAULTS["min_custom_length"]:
                print(f"  Error: Too short. Minumum allowed length is {PASS_DEFAULTS["min_custom_length"]}")
                continue
            return pw

        # Random generation
        elif choice == "1":
            pw_len = get_int(
                f"\n  Enter desired length (minimum {PASS_DEFAULTS["min_length"]}, "
                f"Enter for default of {PASS_DEFAULTS["length"]}): ", 
                default=PASS_DEFAULTS["length"]
                )
            if pw_len is None:
                break
            # Check length
            if pw_len < PASS_DEFAULTS["min_length"]:
                print(f"  Error: Too short. Minumum allowed length is {PASS_DEFAULTS["min_length"]}")
                continue

            if pw_len > PASS_DEFAULTS["max_length"]:
                print(f"  Error: Too long. Maximum allowed length is {PASS_DEFAULTS["max_length"]}")
                continue

            min_upper = PASS_DEFAULTS["min_upper"] or DEFAULT_MIN_FALLBACK
            min_nums = PASS_DEFAULTS["min_digits"] or DEFAULT_MIN_FALLBACK
            min_symbs = PASS_DEFAULTS["min_symbols"] or DEFAULT_MIN_FALLBACK

            try:
                pw = random_password(length = pw_len,
                                      min_upper = min_upper,
                                        min_nums = min_nums,
                                          min_symbs = min_symbs)
            except ValueError as e:
                print (f"\n  {e}")
                continue

            print(f"\n Generated: ", end="", flush= True)
            print_bytearray(pw)
            if input("\n Accept this password? (y/n): ").strip().lower() == "n":
                continue
            return pw
        
        # Passphrase generation
        elif choice == "2":
            diceware = DicewarePassphrase(WORD_LIST) # type: ignore
            pw_len = get_int(
                f"\n  Enter desired number of words. "
                f"Press Enter for default of {PASS_DEFAULTS["phrase_words"]}: ", 
                default=int(PASS_DEFAULTS["phrase_words"])
                )
            if pw_len is None:
                break

            if pw_len > PASS_DEFAULTS["max_phrase_words"]:
                print(f"  Error: Too long. Maximum allowed is {PASS_DEFAULTS["max_phrase_words"]} words")
                continue

            use_nums = input(f"  Include numbers? (y/n) or Enter for default: ")
            if use_nums == "y":
                use_nums = True
            elif use_nums == "n":
                use_nums = False
            else:
                use_nums = PASS_DEFAULTS["phrase_use_nums"]

            pw = bytearray()
            for i in range(pw_len):
                word = diceware.get_word(diceware.roll_5dice())
                word = apply_random_capitalization(word)
                if use_nums:
                    word = apply_random_number(word)

                pw.extend(word)

                if i < pw_len-1:
                    pw.extend(PASS_DEFAULTS["phrase_sep"][randbelow_reject(
                        len(PASS_DEFAULTS["phrase_sep"]))].encode(UTF8))
                    
                del word
                
                
            print(f"\n Generated: ", end="", flush= True)
            print_bytearray(pw)
            if input("\n Accept this password? (y/n): ").strip().lower() == "n":
                continue
            return pw
        
        elif choice == "":
            return None
        elif choice == "d":
            return bytearray(b"")
        else:
            print("Invalid — Selection")

def check_max_consecutive_bytes(pw: bytearray, threshold: int) -> bool:
    '''
    Check if longest run of identical consecutive characters is above threshold.

    Args:
        pw: Password to analyze. (bytearray)
        threshold: The minimum nuymber of consecuritves bytes to allow (int)
    
    Returns:
        True: if > threshold
        False: if <= threshold
    '''
    if not pw:
        return True

    current_run = 1
    prev = pw[0]

    for b in pw[1:]:
        if b == prev:
            current_run += 1
            if current_run > threshold:
                return False
        else:
            current_run = 1
            prev = b

    return True

def apply_random_capitalization(word: bytearray) -> bytearray:
    r = randbelow_reject(3)
    for i, b in enumerate(word):
        if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            # Lowercase, bitwise OR with capital bit. Adds capital bit (0010 0000)
            if r == 0:
                word[i] = b | 0x20
            # Capitalize, bitwise AND with compliment of capital bit. Removes capital bit
            elif r == 1:
                if i == 0:
                    word[i] = b & ~0x20
                else:
                    word[i] = b | 0x20
            # Uppercase
            else:
                word[i] = b & ~0x20
    return word

def apply_random_number(word: bytearray) -> bytearray:
    r = randbelow_reject(4)

    if r == 0:
        return word

    n = randbelow_reject(10)
    num = int_to_ascii_ba(n)

    if r == 1:
        # word + number
        out = bytearray(len(word) + len(num))
        out[:len(word)] = word
        out[len(word):] = num

    elif r == 2:
        # number + word
        out = bytearray(len(word) + len(num))
        out[:len(num)] = num
        out[len(num):] = word

    else:
        # number + word + number
        n2 = randbelow_reject(10)
        num2 = int_to_ascii_ba(n2)

        out = bytearray(len(num) + len(word) + len(num2))
        i = 0
        out[i:i+len(num)] = num
        i += len(num)
        out[i:i+len(word)] = word
        i += len(word)
        out[i:i+len(num2)] = num2

    return out
    
def int_to_ascii_ba(n: int) -> bytearray:
    if n == 0:
        return bytearray(b"0")

    out = bytearray()
    while n > 0:
        out.append(0x30 + (n % 10))  # '0' + digit
        n //= 10

    out.reverse()
    return out

def wipe_byte_arr(buf):
    for i in range(len(buf)):
        buf[i] = 0