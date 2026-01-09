import urllib.parse
import qrcode
import tkinter as tk
import base64
import io
import pyotp
import time
import logging
from utils.Entry import Entry
from config.config_vault import UTF8
from utils.clipboard_utils import copy_to_clipboard

def generate_otp_uri(
    secret,
    label,
    issuer=None,
    type_="totp",
    algorithm="SHA1",
    digits=6,
    period=30,):
    """
    Generate a standard otpauth URI for TOTP/HOTP.

    Constructs a URI compatible with authenticator apps like Google Authenticator.

    Args:
        secret: Base32-encoded secret key.
        label: Label identifying the account.
        issuer: Optional issuer name.
        type_: "totp" (default) or "hotp".
        algorithm: Hash algorithm (default "SHA1").
        digits: Number of code digits (default 6).
        period: Time period in seconds for code refresh (default 30).

    Returns:
        A string containing the otpauth URI.

    Raises:
        ValueError: If secret or label are empty.
    """
    if not secret or not label:
        raise ValueError("secret and label are required")

    label_enc = urllib.parse.quote(label)
    secret = secret.replace(" ", "")

    uri = f"otpauth://{type_}/{label_enc}?secret={secret}"

    if issuer:
        uri += f"&issuer={urllib.parse.quote(issuer)}"

    uri += f"&algorithm={algorithm}&digits={digits}&period={period}"

    return uri

def show_totp_code(entry: Entry, entry_key: bytes, interval=30) -> int:
    """
    Display a live TOTP code for a vault entry.

    Continuously prints the current one-time password, refreshing
    according to the given interval.

    Args:
        entry: Entry containing the TOTP secret.
        interval: Code refresh interval in seconds (default 30).

    Returns:
        0 if user exits via Ctrl+C.
        1 if an unexpected error occurs.

    Side Effects:
        Prints TOTP codes to stdout every second.
    """
    try:
        with entry.get_totp(entry_key) as totp:
            totp = pyotp.TOTP(totp.decode(UTF8))
        print("Generator started. Ctrl + C to stop. \nCode is copied to clipboard\n")
        current_code = totp.now()
        copy_to_clipboard(current_code, timeout=0, prompt= False)
        while (True):
            if not totp.verify(current_code):
                current_code = totp.now()
                copy_to_clipboard(current_code, timeout=0, prompt= False)
            remaining = interval - (int(time.time()) % interval)
            line = f"\r One-time password code: " \
                    f"{current_code[:len(current_code)//2]} {current_code[len(current_code)//2:]}" \
                    f"  (refreshes in {remaining:2d}s)"
            
            print(line, end="", flush=True)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n Stopped.")
        copy_to_clipboard("", timeout=0, prompt= False)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        logging.error(e)
        copy_to_clipboard("", timeout=0, prompt= False)
        return 1

def show_totp_qr(entry: Entry, entry_key: bytes):
    """
    Display a TOTP QR code in a Tkinter window.

    Generates a QR code for the TOTP URI of the entry, along with
    a label displaying site and account. The window auto-closes
    after a short period.

    Args:
        entry: Vault entry containing TOTP secret, site, and account.

    Side Effects:
        - Opens a GUI window with QR code and label.
        - Generates temporary in-memory image data.
        - Automatically closes the window after 15 seconds.

    Security Notes:
        - QR code contains the raw TOTP secret; treat as sensitive.
        - References to image data are cleared after closing.
    """
    with entry.get_totp(entry_key) as totp:
        uri = generate_otp_uri(secret=totp.decode(UTF8), 
                            label=entry.account.capitalize() or 'No Account', 
                            issuer=entry.site.capitalize())
    # Generate QR
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert image -> PNG bytes -> base64
    buf = io.BytesIO()
    img.save(buf, format="PNG") # type: ignore
    png_bytes = buf.getvalue()
    b64_data = base64.b64encode(png_bytes)

    # Tk window
    root = tk.Tk()
    root.title("Scan with Authenticator")

    photo = tk.PhotoImage(data=b64_data)
    lbl_img = tk.Label(root, image=photo)
    lbl_img.image = photo # type: ignore
    lbl_img.pack(padx=20, pady=20)

    uri_box = tk.Text(root, height=4, width=90)
    uri_box.insert("1.0", f"{entry.site.capitalize()}\n{entry.account.capitalize()}")
    uri_box.configure(state="disabled")
    uri_box.pack(padx=10, pady=(0, 10))

    # Bring to front
    root.lift()
    root.attributes("-topmost", True)
    root.after(100, lambda: root.attributes("-topmost", False))
    root.focus_force()

    def on_close():
        nonlocal photo, lbl_img, uri_box, png_bytes, b64_data

        lbl_img.destroy()
        uri_box.destroy()

        # Drop references
        photo = None
        lbl_img = None
        uri_box = None
        png_bytes = None
        b64_data = None

        root.destroy()

    # Set auto close timer
    seconds = 15
    root.after(seconds * 1000, on_close)
    # Remove references on window
    root.protocol("WM_DELETE_WINDOW", on_close)

    root.mainloop()
        