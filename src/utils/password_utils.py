import hashlib
import urllib.request
import csv
import logging
import pendulum
from collections import defaultdict

from zxcvbn import zxcvbn
from utils.vault_utils import decrypt_entry
from config.config_vault import DT_FORMAT_EXPORT, SEP_LG, SITE_LEN, ACCOUNT_LEN
from utils.Entry import Entry

logger = logging.getLogger(__name__)

def pwned_password_count(entry: Entry, timeout: int = 5) -> int:
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
    sha1_hash = hashlib.sha1(entry.password).hexdigest().upper()

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
    except Exception as e:
        msg = f"Error: Could not reach pwnedpasswords API. {e}"
        print(msg)
        logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
        return -1

    # Find the suffix match and get the count
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def strength_analysis(entry: Entry,*,
                      crack_threshold_days=0.5,
                      show_score=False, 
                      show_warning= False, 
                      show_suggestions=False, 
                      show_crack_times=False) -> int:
    """
    Offline password strength analysis using zxcvbn library.
    https://pypi.org/project/zxcvbn/
    Python implementation of the library created by Dropbox.
    Estimates how hard a password is to crack

    Detects:
        Common passwords
        Names, dates, keyboard patterns
        Repeated and sequential patterns
        Returns a score (0-4), crack-time estimates, and feedback

    
    Modified it to add a bonus pointif offline fast hashing 1e10 
    takes longer than x threshold days to crack.

    Returns  - Score 0 (terrible) to 5 (excellent) for password strength 
                (int)
             - -1 if password is empty or None
    """
    if not entry.password:
        return -1
    if len(entry.password) > 100:
        results = zxcvbn(entry.password[:100].decode("utf-8"), max_length=100)
    else:
        results = zxcvbn(entry.password.decode("utf-8"), max_length=100)

    score = results['score']

    if show_score:
        print(f"Analysis results for: {entry.password}")
        print(f"Score 0 (terrible) to 4 (great) : {results['score']}")

    if show_warning and results['feedback']['warning']:
        print(f"\nWarning: {results['feedback']['warning']}")

    if show_suggestions and results['feedback']['suggestions']:
        print ("\nSuggestions:")
        for suggestion in results['feedback']['suggestions']:
            print(f" {suggestion}")
    if show_crack_times:
        print("\nCrack times:")
        for category, time in results['crack_times_display'].items():
            print(f" {category} : {time}")
    
    # Adds a bonus point if offline fast hashing takes more than x days to crack.
    seconds = int(results['crack_times_seconds']['offline_fast_hashing_1e10_per_second'])
    threshold_seconds = 86400 * crack_threshold_days
    if seconds > threshold_seconds:
        score += 1

    return score


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

def audit_vault(encrypted_entries, key: bytes,
                 test_strength=True,
                   test_exposure=False,
                   test_reuse=True,
                     strength_threshold=5) -> list:
    """
    Audits vault passwords for security issues.

    Decrypts vault entries and performs security audits. 
    Including password strength via zxcvbn, 
    data breach checks via pwnedpasswords, and password reuse detection. 
    
    Entries without passwords are ignored.

    Results are printed to the console in a severity-sorted table and may
    optionally be exported to CSV.

    Args:
        encrypted_entries (iterable): Collection of encrypted vault entry
            identifiers.
        key (bytes): Decryption key used to access vault entries.
        test_strength (bool, optional): Whether to evaluate password
            strength. Defaults to True.
        test_exposure (bool, optional): Whether to check passwords against
            known breach data. Defaults to False.
        test_reuse (bool, optional): Whether to detect reused passwords.
            Defaults to True.
        strength_threshold (int, optional): Minimum acceptable password
            strength score. Passwords scoring below this value are flagged.
            Defaults to 5.

    Returns:
        list[dict]: A list of dictionaries representing entries with detected
        issues. Each dictionary contains:
            - "site" (str)
            - "account" (str)
            - "strength" (int | None)
            - "reused" (int | None)
            - "exposures" (int | None)
    """
    print (" Auditing passwords...")
    pw_groups = defaultdict(list)
    results = {}

    final_results = []

    default_strength = -1
    default_exposures = 0
    default_reused = 0

    for eid in encrypted_entries:
        entry = decrypt_entry(encrypted_entries[eid], key, eid)

        # Ignore entries with no password
        if not entry.password:
            continue

        # Initialize result entry
        # None used here for csv export purposes. 
        # NoneType in results/export means it was not tested.
        results[eid] = {
            "eid": eid,
            "site": entry.site,
            "account": entry.account,
            "issues": {
                "strength": None,
                "exposures": None,
                "reused": None
            }
        }

        if test_strength:
            strength = strength_analysis(entry)
            if strength < strength_threshold:
                results[eid]["issues"]["strength"] = strength

        if test_exposure:
            count = pwned_password_count(entry)
            if count > 0:
                results[eid]["issues"]["exposures"] = count
            elif count == -1:
                # Most likely network error. skip the rest of exposure counts
                test_exposure = False

        if test_reuse:
            pw_hash = hashlib.sha256(entry.password).hexdigest()
            # Create password hashmap
            pw_groups[pw_hash].append(eid)

        entry.wipe()
        del entry
    
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
            with open(f"password_audit_{timestamp}.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames= final_results[0].keys()
                )

                writer.writeheader()
                writer.writerows(final_results)
            print (f"Results exported to password_audit_{timestamp}.csv")
        
    return final_results

def audit_entry(entry: Entry,
                encrypted_entries, 
                key: bytes,
                eid: str,
                 test_strength=True,
                   test_exposure=False,
                   test_reuse=True,) -> dict:
    """
    Audits single entry password for security issues.

    """

    # Ignore entries with no password
    if not entry.password:
        return
    
    # Initialize result entry
    # None used here for csv export purposes. 
    # NoneType in results/export means it was not tested.
    results = {
        "site": entry.site,
        "account": entry.account,
        "issues": {
            "strength": None,
            "exposures": None,
            "reused": None
        }
    }
    
    if test_strength:
        strength = strength_analysis(entry, show_crack_times=True)
        results["issues"]["strength"] = strength
        print (f"\nStrength (0-5): {strength}")

    if test_exposure:
        count = pwned_password_count(entry)
        results["issues"]["exposures"] = count
        print (f"\nExposure count: {count}")

    if test_reuse:
        reuse_list = []
        for eid2 in encrypted_entries:
            entry2 = decrypt_entry(encrypted_entries[eid2], key, eid2)
            if entry2.password == entry.password and eid != eid2:
                reuse_list.append(f" Site: {entry2.site}   Account: {entry2.account}")
            entry2.wipe()
            del entry2
        if len(reuse_list) > 0:
            print ("\nReuse detected in the following accounts:")
            for e in reuse_list:
                print (e)
        else:
            print ("\nReuse count: 0")
        results["issues"]["reused"] = len(reuse_list)

    return results
    

# if __name__ == "__main__":
#     password = 'sde3444ter3r4'
#     print (f"\n Password score (0-5) for {password}: {strength_analysis(password,show_crack_times=True)}")
#     print (f"\n number of entries found in database for {password}:  {pwned_password_count(password)}")
