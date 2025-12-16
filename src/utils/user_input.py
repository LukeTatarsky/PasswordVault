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
        if re.fullmatch(r"[0-9]+", val):
            return int(val)
        # Allow quitting with "q"
        if val == 'q':
            return None

        print("   Invalid — numbers only  (q) to quit")




def get_note_from_user(prompt: str = "Enter note:") -> str:
    """
    Prompt the user to enter a multi-line note.

    Input continues until the user presses Enter three times consecutively.
    Pressing Enter once immediately will result in an empty note.

    Args:
        prompt: Text displayed to the user before input begins.

    Returns:
        The entered note with preserved line breaks. Returns an empty string
        if no note content is provided.
    """
    print(f"{prompt} (Enter 3x to end or 1x to leave empty)")
    note = ""
    consecutive_empty = 0

    while True:
        line = input()
        if line == "":
            consecutive_empty += 1
            if consecutive_empty >= 3 or (consecutive_empty == 1 and note == ""):
                break
        else:
            consecutive_empty = 0
            note += line + "\n"

    return note.strip()