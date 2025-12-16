import urllib.parse
import qrcode
import tkinter as tk
import base64
import io
import secrets
import pyotp
import time

def generate_otp_uri(
    secret,
    label,
    issuer=None,
    type_="totp",
    algorithm="SHA1",
    digits=6,
    period=30,
):
    if not secret or not label:
        raise ValueError("secret and label are required")

    label_enc = urllib.parse.quote(label)
    secret = secret.replace(" ", "")

    uri = f"otpauth://{type_}/{label_enc}?secret={secret}"

    if issuer:
        uri += f"&issuer={urllib.parse.quote(issuer)}"

    uri += f"&algorithm={algorithm}&digits={digits}&period={period}"

    return uri

def show_totp_code(totp_key, interval=30) -> None:
    """
    -------------------------------------------------------
    Prompts the user to provide a password with options:
      • Type 'g'    → generate a random password using defaults
      • Type 'c'    → generate a customizable random password
      • Type 'q' → quit
      • Press Enter → manually type a custom password
      
    Use:
        show_totp_code(totp_key)
    -------------------------------------------------------
    Parameters:
        prompt - A promt to the user (str)
                 Defaults to "Password:"
    Returns:
        None
    -------------------------------------------------------
    """
    
    try:
        totp = pyotp.TOTP(totp_key)
        print("Generator started. Ctrl + C to stop.\n")
        current_code = totp.now()
        while (True):
            if not totp.verify(current_code):
                current_code = totp.now()
            remaining = interval - (int(time.time()) % interval)
            line = f"\r One-time password code: " \
                    f"{current_code[:len(current_code)//2]} {current_code[len(current_code)//2:]}" \
                    f"  (refreshes in {remaining:2d}s)"
            
            print(line, end="", flush=True)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n Stopped.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        totp_key = secrets.token_bytes(len(totp_key))
        del totp_key

    return

def show_totp_qr(totp_secret, label, issuer):
    
    uri = generate_otp_uri(secret=totp_secret, label=label,issuer=issuer)
    # Generate QR
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert image -> PNG bytes -> base64
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    b64_data = base64.b64encode(png_bytes)

    # Tk window
    root = tk.Tk()
    root.title("Scan with Authenticator")

    photo = tk.PhotoImage(data=b64_data)
    lbl_img = tk.Label(root, image=photo)
    lbl_img.image = photo
    lbl_img.pack(padx=20, pady=20)

    root.mainloop()



if __name__ == "__main__":

    totp_secret = "VRADA63O2D44Z6Z25TFJQEHMBSJ5GWXA"
    label = "test Label"
    issuer = "test Service"

    show_totp_qr(totp_secret, label, issuer)

    
