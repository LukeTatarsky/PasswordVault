
import pyperclip
import time
import threading
import secrets
import string

from config.config_vault import *

def copy_to_clipboard(text: str | bytearray,
                       timeout: int = CLIPBOARD_TIMEOUT,
                         prompt = True) -> None:
    """
    Copy sensitive text to the system clipboard with optional auto-clear.

    Optionally prompts the user before copying. If a timeout is
    specified, a background daemon thread clears the clipboard after
    the delay to reduce exposure of sensitive data.

    Args:
        text: Text to copy to the clipboard.
        timeout: Number of seconds before the clipboard is cleared.
            A value of 0 or less disables auto-clear.
        prompt: If True, prompt the user before copying. If False,
            copy immediately.

    Returns:
        None

    Side Effects:
        Copies data to the system clipboard.
        Spawns a background daemon thread if auto-clear is enabled.

    Security Notes:
        - Clipboard is cleared after the timeout when enabled.
        - Clipboard history may be wiped depending on configuration.
        - Errors during clipboard operations are suppressed to avoid
          crashing the application.
    """
    if not text:
        print(" Nothing to copy.")
        return
    
    if prompt and input(" Copy to clipboard? (y/n): ").strip().lower() != "y":
        return
    
    # Copy to clipboard
    if isinstance(text, str):
        pyperclip.copy(text)
    elif isinstance(text, bytearray):
        pyperclip.copy(text.decode(UTF8))

    text = " Copied!" + (f" (auto-clears in {timeout}s)" if timeout > 0 else "")
    print(text, flush=True)

    if timeout <= 0:
        return

    def auto_clear():
        time.sleep(timeout)
        try:
            pyperclip.copy("")
            clear_clipboard_history()
        except Exception:
            # prevent clipboard errors from crashing program
            pass

    threading.Thread(target=auto_clear, daemon=True).start()

    return

def clear_clipboard_history(clipboard_length: int = CLIPBOARD_LENGTH):
    """
    Attempt to wipe clipboard history by flooding it with random data.

    Overwrites the clipboard repeatedly with randomly generated strings
    in an effort to evict sensitive entries from clipboard history.
    Behavior depends on platform and clipboard manager capabilities.

    Args:
        clipboard_length: Number of random clipboard entries to generate.

    Returns:
        None

    Side Effects:
        Overwrites the system clipboard multiple times.
        Introduces small delays to avoid clipboard throttling.

    Security Notes:
        - Disabled if WIPE_CLIPBOARD is False in configuration.
        - Best-effort only; some clipboard managers retain long histories.
        - Final clipboard content is a non-sensitive placeholder string.
    """
    # Simple overwrite on exit
    pyperclip.copy("")

    if not WIPE_CLIPBOARD:
        return
    
    char_set = string.ascii_letters + string.digits + "!@#$%^&*"

    for i in range(clipboard_length):
        fake_data = ''.join(secrets.choice(char_set) for _ in range(40))
        fake_data = f"[{i:03d}] {fake_data} - {secrets.token_hex(EID_LEN)}"

        pyperclip.copy(fake_data)
        
        # Defeats throttling
        time.sleep(0.07)

    pyperclip.copy("Clipboard history cleared")
    return