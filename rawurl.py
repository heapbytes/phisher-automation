import re
import quopri
from bs4 import BeautifulSoup
import html

def extract_email_body(raw_data):
    # Step 1: Find the part after "Content-Transfer-Encoding: quoted-printable"
    body_start = re.search(r"Content-Transfer-Encoding: quoted-printable\s*(.*)", raw_data, re.DOTALL)
    
    if not body_start:
        return "No email body found."
    
    # Get the content after the start point
    email_body = body_start.group(1)
    
    # Step 2: Extract up to the next boundary marker
    boundary_match = re.search(r'------=_NextPart_[^\s]+', email_body)
    if boundary_match:
        email_body = email_body[:boundary_match.start()].strip()
    
    # Step 3: Decode quoted-printable encoding
    decoded_body = quopri.decodestring(email_body).decode('utf-8')

    # Step 4: Strip HTML tags
    soup = BeautifulSoup(decoded_body, "html.parser")
    text_body = soup.get_text(separator="\n")

    # Step 5: Decode HTML entities and cleanup
    plain_text = html.unescape(text_body)
    cleaned_text = "\n".join([line.strip() for line in plain_text.splitlines() if line.strip()])

    return cleaned_text

