import hashlib
import urllib.request
import csv
import logging
import re
import pendulum
from collections import defaultdict

from zxcvbn import zxcvbn
from utils.vault_utils import decrypt_entry
from config.config_vault import DT_FORMAT_EXPORT, \
    SEP_LG, SITE_LEN, ACCOUNT_LEN, PASS_DEFAULTS, EXPORT_DIR
from utils.Entry import Entry, str_to_bytes
from utils.crypto_utils import derive_key

logger = logging.getLogger(__name__)

WORD_SEPARATORS = r"[_\-\.\!\s@#\$%\^&\*\+=:~|]+"

def pwned_password_count(e: Entry, vault_key:bytes, timeout: int = 5) -> int:
    """
    This code is derived from the pwnedpasswords Python package
    https://github.com/robertdavidgraham/pwnedpasswords

    Returns the number of times provided password has been found in 
    pwnedpasswords database. 
 
    Retrieves a list of SHA-1 hashes and their count(number of exposures)
    from pwnedpasswords database that match the first 5 chars of SHA-1 hash.

    Locally compares the remaing chars of the hash to match our password.

    Requires internet connection.
    Does not send plaintext password or complete hash.

    Can also use, exact same code.
        count = pwnedpasswords.check(plaintext)
        count = pwnedpasswords.check(sha1_hash)

    Returns  -  number of times password has been found in data breach database
                -1 if any error occurs
    """
    # Hash password with SHA-1
    with e.get_password(derive_key(vault_key, info = str_to_bytes(e.entry_id))) as e_pw:
        sha1_hash = hashlib.sha1(e_pw).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Query pwnedpasswords
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "hibp-password-check"
        }
    )
    try:
        # Retrieve all matched prefixes
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except Exception as er:
        msg = f"Error: Could not reach pwnedpasswords API. {er}"
        print(msg)
        logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
        return -1

    # Find the suffix match and get the count
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0

def heuristic_analysis(pwd: str) -> float:
    """
    Estimate password strength using a rule-based heuristic.

    This analysis evaluates:
    - Character variety (uppercase, lowercase, digits, symbols)
    - Patterns (repeated characters, sequential characters)
    - Middle-character placement

    Args:
        pwd (str): The password to analyze.

    Returns:
        float: Strength score between 0 and 100.
    """
    # Nothing to test
    if not pwd:
        return 0

    # Base values
    password_length = len(pwd)
    score = 0

    # Character type counters
    uppercase_count = 0
    lowercase_count = 0
    digit_count = 0
    symbol_count = 0
    middle_char_count = 0  # Digits or symbols not at the start/end

    # Pattern penalties
    consecutive_uppercase = 0
    consecutive_lowercase = 0
    consecutive_digits = 0
    consecutive_letter = 0
    sequential_letters = 0
    sequential_digits = 0
    sequential_symbols = 0

    # Count character types and middle characters
    for index, char in enumerate(pwd):

        if char.isupper():
            uppercase_count += 1

        elif char.islower():
            lowercase_count += 1

        elif char.isdigit():
            digit_count += 1
            # Digits in the middle are better
            if 0 < index < password_length - 1:
                middle_char_count += 1

        # Symbols = anything not alphanumeric or underscore
        elif re.match(r"[^\w]", char):
            symbol_count += 1
            # Symbols in the middle are better
            if 0 < index < password_length - 1:
                middle_char_count += 1

    # Detect consecutive characters
    for i in range(password_length - 1):
        if pwd[i].isupper() and pwd[i + 1].isupper():
            consecutive_uppercase += 1

        if pwd[i].islower() and pwd[i + 1].islower():
            consecutive_lowercase += 1

        if pwd[i].isdigit() and pwd[i + 1].isdigit():
            consecutive_digits += 1

        if pwd[i].isalpha() and pwd[i + 1].isalpha():
            consecutive_letter += 0.25

    # Detect simple sequential patterns (abc, 123, 321, !@#)
    for i in range(password_length - 2):
        three_chars = pwd[i:i + 3]

        # Alphabetical sequences
        if three_chars.lower() in "abcdefghijklmnopqrstuvwxyz":
            sequential_letters += 1

        # Keyboard sequences l->r
        if three_chars.lower() in "qwertyuiopasdfghjklzxcvbnm":
            sequential_letters += 0.25
        # Keyboard sequences r->l
        if three_chars.lower() in "poiuytrewqlkjhgfdsamnbvcxz":
            sequential_letters += 0.25

        # Numeric sequences
        if three_chars in "01234567890":
            sequential_digits += 1

        if three_chars in "0987654321":
            sequential_digits += 1
        
        # Symbol sequences
        if three_chars in "`~!@#$%^&*()_+/*-+<>?":
            sequential_symbols += 1

        if three_chars in "+-*/?><+_)(*&^%$#@!~`":
            sequential_symbols += 1

    #-----------------------------------------
    # BONUSES
    
    length_bonus = password_length * 4
    score += length_bonus
    # Mixing uppercase with other characters
    if uppercase_count > 0 and uppercase_count < password_length:
        uppercase_bonus = (password_length - uppercase_count) * 2
        score += uppercase_bonus

    # Mixing lowercase with other characters
    if lowercase_count > 0 and lowercase_count < password_length:
        lowercase_bonus = (password_length - lowercase_count) * 2
        score += lowercase_bonus

    # Numbers and symbols increase entropy
    number_bonus = digit_count * 4
    score += number_bonus
    symbol_bonus = symbol_count * 6
    score += symbol_bonus

    # Middle characters are harder to guess
    middle_bonus = middle_char_count * 2
    score += middle_bonus

    #-----------------------------------------
    # PENALTIES
    
    # Repeated characters lower entropy
    def repetition_penalty(pwd: str) -> int:
        #Severely punishes repetition such as aaaaaabbbbbbbbcccccc

        length = len(pwd)
        if length == 0:
            return 0
        
        len_set = len(set(pwd))
        repeated_char_count = password_length - len_set

        repetition_ratio = repeated_char_count / length

        if repetition_ratio >= 0.8:
            penalty = (repetition_ratio * 10) ** 2.6
        else:
            penalty = (repetition_ratio * 10) ** 2.16

        # Reduce penalty for multi-word passphrases
        # Split on passphrase separators
        escaped_separators = [re.escape(s) for s in PASS_DEFAULTS['phrase_sep']]
        pattern = "[" + "".join(escaped_separators) + "]"

        # Dont bother if the pw is aaaaa-bbbbbb-cccccc-ddddd
        if repetition_ratio <= 0.7:
            words = re.split(pattern, pwd)
            if len(words) >= 3:
                penalty *= 0.15  # mild impact for long passphrases

        return penalty
    
    repeat_penalty = repetition_penalty(pwd)
    score -= repeat_penalty

    # Consecutive character penalties
    consecutive_upper_pen = consecutive_uppercase * 2
    consecutive_lower_pen = consecutive_lowercase * 2
    consecutive_digits_pen = consecutive_digits * 2
    score -= consecutive_upper_pen + consecutive_lower_pen + consecutive_digits_pen

    score -= consecutive_letter 

    # Sequential pattern penalties
    score -= (
        sequential_letters + 
        sequential_digits + 
        sequential_symbols
    ) * 4

    # Final heuristic score 0–100
    score = max(0, min(score, 100))
    return score

def raw_quantum_bonus(log10_guesses: float) -> float:
        """
        Compute a post-quantum bonus score based on estimated password entropy.

        The bonus is assigned according to the following tiers:

        Bonus tiers:

            Tier               | pq_log10_guesses | Bonus   | Meaning
            -------------------|----------------|--------|-------------------------------
            Weak               | < 10           | 0      | Trivially breakable
            Fair               | 10 - 18        | 0 - 2  | Breakable with moderate resources
            Strong             | 18 - 26        | 2 - 12 | Expensive to crack
            Exceptional        | 26 - 38        | 12 - 36| Nation-state hard
            Quantum Resistant  | ≥ 38           | 38     | Post-quantum infeasible

        Args:
            log10_guesses (float): log10 of estimated number of guesses required for a classical attacker.

        Returns:
            float: Quantum bonus score (0-38) reflecting post-quantum cracking difficulty.
        """
        pq_log10_guesses = log10_guesses / 2

        bonus = 0

        if pq_log10_guesses > 10:
            # Classical: Expensive but achievable with scaled attacks
            # Post-quantum: Weak
            # Minor bonus for pq_log10_guesses > 10
            bonus += min(pq_log10_guesses - 10, 8) * 0.25

        if pq_log10_guesses < 18:
            pass
        
        elif pq_log10_guesses < 26:
            # Very Strong
            # Classical: infeasible for most attackers
            # Post-quantum: still theoretically crackable
            bonus += (pq_log10_guesses - 18) * 1.5
        
        elif pq_log10_guesses < 38:
            # Exceptional
            # Classical: Beyond realistic brute-force
            # Post-quantum: Approaching nation-state hard
            bonus += 12 + (pq_log10_guesses - 26) * 2
        else:
            # Quantum Resistant
            # Post-quantum brute-force is infeasible
            # 100% Score
            bonus += 36

        return bonus

def scale_quantum_bonus(log10_guesses: float, raw_bonus: float) -> float:
    """
    Scales a raw post-quantum bonus into a percentage-based score.

    The scaling is performed in two stages based on post-quantum entropy
    (pq_log10_guesses = log10_guesses / 2):

        Stage 1 (pq ≤ 18):
            Raw bonus 0-2 → 0-20%

        Stage 2 (pq > 18):
            Raw bonus 2-38 → 20-100%

    Args:
        log10_guesses (float): log10 of estimated classical brute-force guesses.
        raw_bonus (float): Unscaled quantum bonus derived from entropy tiers.

    Returns:
        float: Scaled quantum bonus as a percentage (0-100).
    """
    RAW_AT_18 = 2
    RAW_MAX = 38
    STAGE1_MAX = 20
    pq_log10_guesses = log10_guesses / 2
    
    # Stage 1: up to pq=18 → scale into 0–STAGE1_MAX
    if pq_log10_guesses <= 18:
        return round((raw_bonus / RAW_AT_18) * STAGE1_MAX, 1)

    # Stage 2: 18+ → scale remaining into STAGE1_MAX–100
    return round(
        STAGE1_MAX + ((raw_bonus - RAW_AT_18) / (RAW_MAX - RAW_AT_18)) * (100 - STAGE1_MAX), 1)


def compress_password(pwd: str) -> str:
    """
    Compress a password by collapsing repeated characters, repeated sequences, and repeated words.

    1. Collapsing consecutive repeated characters.
    2. Collapsing consecutive repeated words (split by separators).
    3. Collapsing repeated sequences of characters (e.g., 'VeryVeryVery' -> 'Very').

    Args:
        pwd (str): Password to compress.

    Returns:
        str: Compressed password.
    """
    if not pwd:
        return ""

    # -----------------------
    # Step 1: Compress repeated characters

    compressed_chars = [pwd[0]]
    for c in pwd[1:]:
        if c != compressed_chars[-1]:
            compressed_chars.append(c)
    pwd_chars = "".join(compressed_chars)

    # -----------------------
    # Step 2: Compress repeated sequences

    # e.g. VeryVeryVery -> Very
    max_seq_len = len(pwd_chars) // 2
    s = pwd_chars
    for seq_len in range(max_seq_len, 0, -1):
        pattern = f"(.{{{seq_len}}})\\1+"  # repeated sequence
        s = re.sub(pattern, r"\1", s)

    pwd_seq = s
    
    # -----------------------
    # Step 3: Compress repeated words

    words = re.split(WORD_SEPARATORS, pwd_seq)
    if not words:
        return pwd_seq

    compressed_words = [words[0]]
    for w in words[1:]:
        if w != compressed_words[-1]:
            compressed_words.append(w)

    # Rejoin using the first separator found (fallback to '-')
    separator_match = re.search(WORD_SEPARATORS, pwd_seq)
    sep = separator_match.group(0) if separator_match else "-"
    
    return sep.join(compressed_words)


def strength_analysis(e: Entry, vault_key: bytes, *,
                                show_details:bool =False,
                                  crack_time_threshold:int = 10_000) -> float:
    """
    Perform a comprehensive password strength analysis for a vault entry.

    This function combines:
    - Heuristic analysis (0-100)
    - zxcvbn entropy estimation (0-100)
    - Post-quantum heuristic bonus (0-100)

    Args:
        e (Entry): Vault entry containing encrypted password.
        vault_key (bytes): Master key for entry decryption.
        show_details (bool, optional): Print detailed analysis. Defaults to False.
        crack_time_threshold (int, optional): Threshold in seconds for fast hashing. Defaults to 10_000.

    Returns:
        float: Combined password strength score (0-100).
    """
    with e.get_password(derive_key(vault_key, info = str_to_bytes(e.entry_id))) as e_pw:
        pwd = e_pw.decode("utf-8")

    # Cut long passwords
    max_zx_len = 100
    if len(pwd) > max_zx_len:
        pwd = pwd[:max_zx_len]
    
    # Make a second copy with any repititions removed
    pw_compressed = compress_password(pwd)

    # Run the test on both compressed and not compressed passwords
    zx_results1 = zxcvbn(password=pwd, max_length=max_zx_len)
    zx_results2 = zxcvbn(password=pw_compressed, max_length=max_zx_len)

    # Take the lowest score results
    if zx_results1["score"] <= zx_results2["score"]:
        zx_results = zx_results1
    else:
        zx_results = zx_results2

    zxcvbn_score = zx_results["score"]
    crack_time = zx_results["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
    warnings = zx_results["feedback"]["warning"]
    suggestions = zx_results["feedback"]["suggestions"]
    log10_guesses = zx_results["guesses_log10"]

    # Set a base score 0-4 to 0–100
    zxcvbn_score = zxcvbn_score * 25

    if crack_time_threshold > 1:
        # zxcvbn_score is too skewed. This alters the score based on fast crack times. 
        if zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold / 1000:
            zxcvbn_score = 0
        elif zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold / 100:
            zxcvbn_score = 10
        elif zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold:
            zxcvbn_score = 20
        elif zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold * 10:
            zxcvbn_score = 50
        elif zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold * 40:
            zxcvbn_score = 60
        elif zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"] < crack_time_threshold * 65:
            zxcvbn_score = 90
        else:
            zxcvbn_score = 100
        
    # Calculate Heuristic Score for nboth compressed and non compressed 
    heuristic_score1 = heuristic_analysis(pwd=pwd)
    heuristic_score2 = heuristic_analysis(pwd=pw_compressed)
    pw_len = len(pwd)
    del pwd, pw_compressed

    # Take the lowest
    heuristic_score = min(heuristic_score1, heuristic_score2)

    # Calculate Quantum Score
    quantum_raw_bonus = raw_quantum_bonus(log10_guesses)
    quantum_score = scale_quantum_bonus(log10_guesses, quantum_raw_bonus)

    # Combine scores
    final_score = round((
        heuristic_score * 0.45 +
        zxcvbn_score * 0.45 +
        quantum_score * 0.10
        ),2)
    
    # Debugging
    # print(f"{zxcvbn_score},{round(heuristic_score, 0):3},{round(quantum_score, 0):3},{final_score},{e.account},{pwd},{zx_results["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"]} ")

    # Define the score
    if final_score < 20:
        verdict = "Unacceptable"
    elif final_score < 30:
        verdict = "Extremely Weak"
    elif final_score < 40:
        verdict = "Very Weak"
    elif final_score < 50:
        verdict = "Weak"
    elif final_score < 60:
        verdict = "Acceptable"
    elif final_score < 70:
        verdict = "Decent"
    elif final_score < 80:
        verdict = "Strong"
    elif final_score < 90:
        verdict = "Pretty Strong"
    elif final_score < 90.5:
        verdict = "Very Strong"
    elif final_score < 91:
        verdict = "Super Strong"
    elif final_score < 95:
        verdict = "Exceptional"
    elif final_score < 100:
        verdict = "Extraordinary"
    else:
        verdict = "Post-Quantum Resistant"

    # Print details
    if show_details:
        print(f"\n--Combined Strength Score Details--")
        print(f"\nFinal Score: {final_score}%")
        print(f"\nVerdict: {verdict}")
        print(f"Heuristic Score: {round(heuristic_score,0)}%")
        print(f"zxcvbn Score: {round(zxcvbn_score,0)}%")
        print(f"Quantum Score: {round(quantum_score,0)}%")
        print(f"Crack Time (fast hash 1e10): {crack_time}")
        print(f"Post Quantum log10 Guesses: {round(log10_guesses/2,1)}")
        print(f"PW Length: {pw_len}")
        if warnings:
            print(f"Warnings: {warnings}")
        if suggestions:
            print(f"Suggestions: {suggestions}")

    return final_score

def severity(result_entry):
    """
    Return a sortable severity key for a vault entry.

    Entries are ranked by exposure count (higher first), password strength
    (lower first), and reuse count (higher first). Missing values are handled
    safely and sorted last.

    Args:
        entry: Vault entry containing an "issues" dictionary.

    Returns:
        A tuple usable as a sort key.
    """
    issues = result_entry["issues"]

    # Top priority is password exposures
    exposures_val = issues.get("exposures") or 0
    # Negate exposure, higher value is higher priority
    exposures_val = -exposures_val

    # Second priority is Strength
    # lowest strength is high priority
    strength = issues.get("strength")
    strength_val = strength if strength is not None else 99

    # Then reuse count
    reused = issues.get("reused")
    reused_val = reused if reused is not None else 0
    # Negate reuse, higher value is higher priority
    reused_val = -reused_val


    return (exposures_val, strength_val, reused_val)

def audit_vault(encrypted_entries, vault_key: bytes,
                 test_strength=True,
                   test_exposure=False,
                   test_reuse=True,
                     strength_threshold=100) -> list:
    """
    Audit multiple vault entries for password security issues.

    Evaluates:
    - Password strength (zxcvbn + heuristic)
    - Breach exposure (pwnedpasswords)
    - Password reuse

    Args:
        encrypted_entries (iterable): Collection of encrypted vault entries.
        vault_key (bytes): Master key used for decryption.
        test_strength (bool, optional): Whether to check password strength. Defaults to True.
        test_exposure (bool, optional): Whether to check for breaches. Defaults to False.
        test_reuse (bool, optional): Whether to detect reused passwords. Defaults to True.
        strength_threshold (int, optional): Minimum acceptable password score. Defaults to 100.

    Returns:
        list[dict]: List of entries with issues. Each dict contains:
            - site (str)
            - account (str)
            - strength (int | None)
            - reused (int | None)
            - exposures (int | None)
    """
    print (" Auditing passwords...")
    pw_groups = defaultdict(list)
    results = {}

    final_results = []

    default_strength = -1
    default_exposures = 0
    default_reused = 0

    for eid in encrypted_entries:
        entry_key = derive_key(vault_key, info = str_to_bytes(eid))
        e = decrypt_entry(str_to_bytes(encrypted_entries[eid]), entry_key, eid)

        # Ignore entries with no password
        if not e.field_exists('password'):
            continue

        # Initialize result entry
        # None used here for csv export purposes. 
        # NoneType in results/export means it was not tested.
        results[eid] = {
            "eid": eid,
            "site": e.site,
            "account": e.account,
            "issues": {
                "strength": None,
                "exposures": None,
                "reused": None
            }
        }

        if test_strength:
            strength = strength_analysis(e,vault_key)
            if strength < strength_threshold:
                results[eid]["issues"]["strength"] = strength

        if test_exposure:
            count = pwned_password_count(e,vault_key)
            if count > 0:
                results[eid]["issues"]["exposures"] = count
            elif count == -1:
                # Most likely network error. skip the rest of exposure counts
                test_exposure = False

        if test_reuse:
            with e.get_password(derive_key(vault_key, info = str_to_bytes(eid))) as e_pw:
                pw_hash = hashlib.sha256(e_pw).hexdigest()
            # Create password hashmap
            pw_groups[pw_hash].append(eid)

        del e
    
    # Mark reused passwords if a group is larger than one
    if test_reuse:
        for eids in pw_groups.values():
            if len(eids) > 1:
                for eid in eids:
                    results[eid]["issues"]["reused"] = len(eids)

    # Console output
    print("\n     Password Issues Found  (Sorted by severity)")
    print(SEP_LG)
    print(f"{'Site':{SITE_LEN}} {'Account':{ACCOUNT_LEN}} Issues")
    print(SEP_LG)

    # Finalize results
    # Sort results based on priority function
    for eid, result_entry in sorted(results.items(), key=lambda x: severity(x[1])):
        issues = result_entry.get('issues')

        strength = issues.get("strength")
        strength = strength if strength is not None else default_strength

        reused = issues.get("reused")
        reused = reused if reused is not None else default_reused
        
        exposures = issues.get("exposures") or default_exposures
        
        weak_pw = (
            test_strength
            and strength > default_strength
            and strength < strength_threshold
        )

        reused_pw = (
            test_reuse
            and reused > default_reused
        )

        exposed_pw = (
            test_exposure
            and exposures > default_exposures
        )

        # Only keep problematic entries
        if weak_pw or exposed_pw or reused_pw:
            site = result_entry.get('site')
            if len(site) >= SITE_LEN:
                site = site[:SITE_LEN-4] + "..."

            account = result_entry.get('account')
            if len(account) >= ACCOUNT_LEN:
                account = account[:ACCOUNT_LEN-4] + "..."

            line = f"{site:{SITE_LEN}} {account:{ACCOUNT_LEN}}"
            if weak_pw:
                line += f"Strength: {strength}"

            if reused_pw:
                line += f" | Reused: {reused:2}"
            else:
                line += " " * 13

            if exposed_pw:
                line += f" | Exposures: {exposures}"

            print(line)

            # mask accounts for export
            account = result_entry.get("account", "")
            # masked_account = account[:5]+ "..." if len(account) > 5 else account
            masked_account = account

            final_results.append({
                "site": result_entry.get("site", ""),
                "account": masked_account,
                "strength": issues.get("strength"),
                "reused": issues.get("reused", None),
                "exposures": issues.get("exposures", None),
            })
        
    if not final_results:
        print("\n   Congratulations Zero Issues Found")

    else:
        # Optionally export the results to csv.
        export = input("\n Would you like to export these results? (y/n) :").strip()

        if export == "y":
            timestamp = pendulum.now().format(DT_FORMAT_EXPORT)
            with open(EXPORT_DIR / f"password_audit_{timestamp}.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames= final_results[0].keys()
                )

                writer.writeheader()
                writer.writerows(final_results)
            print (f"Results exported to password_audit_{timestamp}.csv")
        
    return final_results

def audit_entry(e: Entry,
                encrypted_entries, 
                vault_key: bytes,
                 test_strength=True,
                   test_exposure=False,
                   test_reuse=True,) -> dict:
    """
    Audit a single vault entry for password issues.

    Performs optional:
    - Strength analysis
    - Breach exposure check
    - Password reuse detection

    Args:
        e (Entry): Vault entry to audit.
        encrypted_entries (dict): Collection of all encrypted entries.
        vault_key (bytes): Master key for decryption.
        test_strength (bool, optional): Enable strength analysis. Defaults to True.
        test_exposure (bool, optional): Enable breach checking. Defaults to False.
        test_reuse (bool, optional): Enable password reuse detection. Defaults to True.

    Returns:
        dict: Dictionary containing:
            - site (str)
            - account (str)
            - issues (dict): Contains strength, exposures, reused.
    """

    # Ignore entries with no password
    if not e.field_exists('password'):
        return {}
    
    # Initialize result entry
    # None used here for csv export purposes. 
    # NoneType in results/export means it was not tested.
    results = {
        "site": e.site,
        "account": e.account,
        "issues": {
            "strength": None,
            "exposures": None,
            "reused": None
        }
    }
    eid_b = str_to_bytes(e.entry_id)

    if test_strength:
        strength_analysis(e, vault_key, show_details=True)

    if test_exposure:
        count = pwned_password_count(e, vault_key)
        results["issues"]["exposures"] = count
        print (f"\nExposure count: {count}")

    if test_reuse:
        reuse_list = []
        for eid2 in encrypted_entries:
            eid2_b = str_to_bytes(eid2)
            entry2_key = derive_key(vault_key, info = eid2_b)
            entry2 = decrypt_entry(str_to_bytes(encrypted_entries[eid2]), entry2_key, eid2)
            with e.get_password(derive_key(vault_key, info = eid_b)) as e_pw:
                if entry2.field_exists('password'):
                    with entry2.get_password(entry2_key) as e2_pw:
                        if e_pw == e2_pw and eid_b != eid2_b:
                            reuse_list.append(f" Site: {entry2.site}   Account: {entry2.account}")
            del entry2
        if len(reuse_list) > 0:
            print ("\nReuse detected in the following accounts:")
            for e in reuse_list:
                print (e)
        else:
            print ("\nReuse count: 0")
        results["issues"]["reused"] = len(reuse_list)

    return results
    