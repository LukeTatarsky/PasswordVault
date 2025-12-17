import hashlib
import urllib.request
import csv
import pendulum
from collections import defaultdict

from zxcvbn import zxcvbn
from .vault_utils import get_entry_data
from config.config_vault import DT_FORMAT_EXPORT, SEP_LG, SITE_LEN, ACCOUNT_LEN


def pwned_password_count(password: str, timeout: int = 5) -> int:
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
    """
    # Hash password with SHA-1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

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
    # Retrieve all matched prefixes
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")

    # Find the suffix match and get the count
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def strength_analysis(password: str,*,
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
    if not password:
        return -1
    
    results = zxcvbn(password, max_length=150)
    score = results['score']

    if show_score:
        print(f"Analysis results for: {password}")
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


def severity(entry):
    """
    Computes a sortable severity key for a vault entry.

    Produces a tuple that can be used as a sorting key to
    prioritize password issues. Sorting is performed lexicographically
    on the returned tuple, with lower values indicating higher severity.

    Severity priority order:
      1. Password exposures (higher count = higher severity)
      2. Password strength (lower strength = higher severity)
      3. Password reuse count (higher count = higher severity)

    Untested values (None) are handled safely and sorted last.

    Args:
        entry (dict): A vault entry containing an "issues" dictionary
            with optional keys:
            - "strength" (int | None): Password strength score.
            - "exposures" (int | None): Number of known exposures.
            - "reused" (int | None): Number of times the password is reused.

    Returns:
        tuple[int, int, int]: A tuple suitable for use as a sort key:
            (exposures_priority, strength_priority, reuse_priority).
    """
    issues = entry["issues"]

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
    
    pw_groups = defaultdict(list)
    results = {}

    final_results = []

    default_strength = -1
    default_exposures = 0
    default_reused = 0

    for eid in encrypted_entries:
        data = get_entry_data(encrypted_entries, key, eid)

        site = data.get("site", "")
        account = data.get("account", "")
        pw = data.get("password", "")

        del data

        # Ignore entries with no password
        if not pw:
            continue

        # Initialize result entry
        # None used here for csv export purposes. 
        # NoneType in results/export means it was not tested.
        results[eid] = {
            "eid": eid,
            "site": site,
            "account": account,
            "issues": {
                "strength": None,
                "exposures": None,
                "reused": None
            }
        }

        if test_strength:
            strength = strength_analysis(pw)
            if strength < strength_threshold:
                results[eid]["issues"]["strength"] = strength

        if test_exposure:
            count = pwned_password_count(pw)
            if count > 0:
                results[eid]["issues"]["exposures"] = count

        if test_reuse:
            pw_hash = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            # Create password hashmap
            pw_groups[pw_hash].append(eid)

        del pw, site, account
    
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
    for eid, entry in sorted(results.items(), key=lambda x: severity(x[1])):
        issues = entry.get('issues')

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
            site = entry.get('site')
            if len(site) >= SITE_LEN:
                site = site[:SITE_LEN-4] + "..."

            account = entry.get('account')
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
            account = entry.get("account", "")
            masked_account = account[:5]+ "..." if len(account) > 5 else account[:5]

            final_results.append({
                "site": entry.get("site", ""),
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
                    fieldnames=["site", "account", "strength", "reused", "exposures"]
                )

                writer.writeheader()
                writer.writerows(final_results)
            print (f"Results exported to password_audit_{timestamp}.csv")
        
    return final_results

if __name__ == "__main__":
    
    password = 'sde3444ter3r4'
    print (f"\n Password score (0-5) for {password}: {strength_analysis(password,show_crack_times=True)}")
    print (f"\n number of entries found in database for {password}:  {pwned_password_count(password)}")
