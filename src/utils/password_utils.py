from zxcvbn import zxcvbn
import hashlib
import urllib.request

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


def audit_vault(encrypted_entries, key) -> dict:
    """Runs all password audits and returns a summary."""

def find_reused_passwords(entries: list[dict]) -> dict:
    """Finds passwords reused across multiple entries."""



if __name__ == "__main__":
    
    password = 'sde3444ter3r4'
    print (f"\n Password score (0-5) for {password}: {strength_analysis(password,show_crack_times=True)}")
    print (f"\n number of entries found in database for {password}:  {pwned_password_count(password)}")
