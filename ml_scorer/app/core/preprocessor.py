import urllib.parse
import re

def master_preprocess(text: str) -> str:
    if not isinstance(text, str) or not text:
        return ""
    
    decoded = text
    # Attempt to decode up to 3 times (handle double encoding)
    for _ in range(3):
        try:
            temp = urllib.parse.unquote(decoded)
            if temp == decoded:
                break
            decoded = temp
        except Exception:
            break
    
    decoded = decoded.lower()
    # Normalize whitespace
    decoded = re.sub(r'\s+', ' ', decoded).strip()
    return decoded