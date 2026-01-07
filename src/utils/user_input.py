import re


def get_int(prompt: str, default=None, reprompt=True):
    """
    Prompt the user until a valid positive integer is entered.

    Allows the user to press Enter to accept a default value if provided.
    Rejects any input containing non-digit characters. Optionally allows
    bypassing user input and returning the default directly.

    Args:
        prompt: Text displayed to the user.
        default: Value returned if the user submits empty input. If None,
            the prompt repeats until a valid integer is entered.
        reprompt: If False, bypasses user input and returns the default.

    Returns:
        An integer parsed from user input, the default value if accepted,
        or None if the user enters 'q' to quit.
    """
    while True:
        val = input(prompt).strip() if reprompt else default

        # User hit enter for default value
        # return default if provided, else keep asking
        if not val and default is not None:
            return default
        # User typed something, check it, return if integer
        if re.fullmatch(r"[0-9]+", val): # type: ignore
            return int(val) # type: ignore
        # Allow quitting with "q"
        if val == 'q':
            return None

        print("   Invalid — numbers only  (q) to quit")




def get_note_from_user(prompt: str = "Enter note:") -> str | None:
    """
    Prompt the user to enter a multi-line note.

    Input continues until the user presses Enter three times consecutively.
    Pressing Enter once immediately will result in an empty note.

    Args:
        prompt: Text displayed to the user before input begins.

    Returns:
        str - The entered note with preserved line breaks.
        empty str - if user types "del"
        None - if user enters "q" or hits enter on first input
    """
    print(f"{prompt} (Type in note then Enter 3x to finish, 'del' to delete note, or 'q' to cancel)")
    lines  = []
    consecutive_empty = 0

    while True:
        line = input()
        if line.strip().lower() == "q" and not lines:
            return None
        if len(line.strip()) == 0 and not lines:
            return None
        if line.strip().lower() == "del" and not lines:
            return ''
        
        if line == "":
            consecutive_empty += 1
            if consecutive_empty >= 3 or (consecutive_empty == 1 and not lines):
                break
            lines.append("")  # preserve newline
        else:
            consecutive_empty = 0
            lines.append(line)

    return "\n".join(lines[:-2])


def get_keys_from_user(prompt: str = "Enter keys") -> bytearray | None:
    """
    Prompt the user to enter a multi-line recovery key, displayed on screen.

    Rules:
    - If the first line is exactly 'del' (case-insensitive), return empty byte array.
    - If the first line is exactly 'q' (case-insensitive), return None.
    - Otherwise, keep reading lines until three consecutive empty lines are entered.
    - Preserves line breaks.

    Returns:
        bytearray containing the recovery key.
        empty bytearray to delete keys
        None if user cancels
    """
    print(f"{prompt} (Type in keys then Enter 3x to finish, 'del' to delete keys, or 'q' to cancel) :")
    lines  = []
    consecutive_empty = 0

    while True:
        line = input()
        if line.strip().lower() == "q" and not lines:
            return None
        if len(line.strip()) == 0 and not lines:
            return None
        if line.strip().lower() == "del" and not lines:
            return bytearray(b'')

        if line == "":
            consecutive_empty += 1
            if consecutive_empty >= 3 or (consecutive_empty == 1 and not lines):
                break
            lines.append("")  # preserve newline
        else:
            consecutive_empty = 0
            lines.append(line)

    # Convert to bytearray immediately
    result = bytearray("\n".join(lines[:-2]).encode("utf-8"))

    # Best-effort cleanup of the string inputs
    lines.clear()
    del lines

    return result

def get_totp_from_user(prompt: str = "Enter key") -> bytearray | None:
    """
    Prompt the user to enter a multi-line recovery key, displayed on screen.

    Rules:
    - If input is empty, return empty bytearray.
    - If input is exactly 'q' (case-insensitive), return None.
    - Otherwise, return bytearray of key entered.

    Returns:
        bytearray containing the key.
        None if user cancels
    """
    print(f"{prompt} ('del' to delete keys, or 'q' to cancel) :")

    line = input()
    if line.strip().lower() == "q" or len(line.strip()) == 0:
        return None

    if line.strip().lower() == "del":
        return bytearray(b'')

    # Convert to bytearray immediately
    result = bytearray("".join(line.split()).encode("utf-8"))

    # Best-effort cleanup of the string input
    del line
    return result