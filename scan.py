import os
import imaplib
import email
import re
import requests
import smtplib
import logging
import hashlib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
from html import escape
from bs4 import BeautifulSoup
from io import BytesIO
from base64 import b64encode
from PIL import Image, ImageDraw

# Load environment variables from .env file if present
load_dotenv()

# Configurations from environment variables
IMAP_SERVER = os.getenv('IMAP_SERVER')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))  # Default to 587 if not set
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# File to store processed email IDs
PROCESSED_EMAILS_FILE = 'processed_emails.txt'
REPORT_EMAIL_TITLE = 'Malicious URLs and Attachments Detected in Recent Emails'

# Set up logging, excluding sensitive information
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_processed_emails():
    """Load the list of processed email IDs from a file."""
    if not os.path.exists(PROCESSED_EMAILS_FILE):
        return set()
    with open(PROCESSED_EMAILS_FILE, 'r') as file:
        processed_emails = set(line.strip() for line in file.readlines())
    return processed_emails

def save_processed_email(email_id):
    """Save a processed email ID to the file."""
    with open(PROCESSED_EMAILS_FILE, 'a') as file:
        file.write(f"{email_id}\n")

def access_email():
    """Access and login to the email server securely."""
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select('inbox')
        logging.info("Email login successful.")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to login to email: {e}")
        raise

def fetch_unread_emails(mail):
    """Fetch unread emails from the inbox securely."""
    try:
        status, messages = mail.search(None, '(UNSEEN)')
        email_ids = messages[0].split()
        logging.info(f"Found {len(email_ids)} unread emails.")
        return email_ids
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to fetch unread emails: {e}")
        raise

def extract_links(email_body):
    """Extract and sanitize URLs from the email body."""
    urls = set()  # Use a set to avoid duplicate URLs

    # Use BeautifulSoup to parse the HTML content
    soup = BeautifulSoup(email_body, 'html.parser')
    
    # Extract all href links
    for link in soup.find_all('a', href=True):
        url = link['href']
        sanitized_url = clean_url(url)
        urls.add(sanitized_url)
    
    # Extract URLs directly from the text using regex as a fallback
    regex_urls = re.findall(r'(https?://[^\s]+)', email_body)
    for url in regex_urls:
        sanitized_url = clean_url(url)
        urls.add(sanitized_url)
    
    logging.info(f"Extracted {len(urls)} sanitized URLs.")
    return list(urls)

def clean_url(url):
    """Sanitize and clean a URL."""
    return re.sub(r'[^\w\-._~:/?#[\]@!$&\'()*+,;=%]', '', url)

def check_link_virustotal(url):
    """Check a single URL on VirusTotal and return the detailed scan results."""
    try:
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params={
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': url
            },
            timeout=10  # Set a timeout for the request
        )
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)

        result = response.json()
        if 'scans' in result and 'positives' in result:
            malicious_count = result['positives']
            total_count = result['total']
            details = []

            for engine, scan in result['scans'].items():
                if scan['detected']:
                    details.append(f"{engine}: {scan['result']}")

            logging.info(f"Checked URL {url}: {malicious_count}/{total_count} malicious reports.")
            return {
                'malicious_count': malicious_count,
                'total_count': total_count,
                'details': details,
                'permalink': result.get('permalink')
            }
        else:
            logging.warning(f"No analysis results found for URL: {url}")
            return None

    except requests.RequestException as e:
        logging.error(f"Request failed for URL {url}: {e}")
        return None

def calculate_hash_from_bytes(byte_data):
    """Calculate the SHA-256 hash from bytes."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()

def check_file_virustotal(byte_data, filename):
    """Check a file on VirusTotal using its hash and return the detailed scan results."""
    file_hash = calculate_hash_from_bytes(byte_data)
    logging.info(f"Calculated SHA-256 hash for {filename}: {file_hash}")
    
    try:
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/file/report',
            params=params,
            timeout=10  # Set a timeout for the request
        )
        response.raise_for_status()
        
        result = response.json()
        if 'scans' in result and 'positives' in result:
            malicious_count = result['positives']
            total_count = result['total']
            details = []

            for engine, scan in result['scans'].items():
                if scan['detected']:
                    details.append(f"{engine}: {scan['result']}")

            logging.info(f"File hash {file_hash}: {malicious_count}/{total_count} malicious reports.")
            return {
                'filename': filename,
                'malicious_count': malicious_count,
                'total_count': total_count,
                'details': details,
                'permalink': result.get('permalink')
            }
        else:
            logging.warning(f"No analysis results found for file hash: {file_hash}")
            return None

    except requests.RequestException as e:
        logging.error(f"Request failed for file hash {file_hash}: {e}")
        return None

def process_email(email_id, mail):
    """Process a single email to extract and check URLs and attachments securely."""
    try:
        status, data = mail.fetch(email_id, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])

        # Extract email sender and subject
        sender = msg.get('From', 'Unknown sender')
        subject = msg.get('Subject', 'No subject')

        # Check if the email subject matches REPORT_EMAIL_TITLE and skip if it does
        if subject == REPORT_EMAIL_TITLE:
            logging.info(f"Skipping email ID {email_id} with subject matching report title.")
            return "", None, None, None

        email_body = None
        attachments = []

        if msg.is_multipart():
            # If the email is multipart, extract the payloads
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Check if the content is text/plain or text/html and not an attachment
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        byte_data = part.get_payload(decode=True)
                        attachments.append((byte_data, filename))
                elif content_type == "text/plain":
                    if not email_body:
                        email_body = part.get_payload(decode=True).decode()
                elif content_type == "text/html":
                    if not email_body:  # Prefer plain text if available, otherwise use HTML
                        email_body = part.get_payload(decode=True).decode()
        else:
            # Non-multipart message, directly get the payload
            email_body = msg.get_payload(decode=True).decode()

        if not email_body:
            logging.warning(f"No suitable content found in email ID {email_id}.")
            return "", None, None, None

        urls = extract_links(email_body)
        malicious_report = ""
        findings = []

        # Check URLs
        if urls:
            for url in urls:
                scan_result = check_link_virustotal(url)
                if scan_result:
                    findings.append({
                        'type': 'URL',
                        'value': url,
                        'details': scan_result['details'],
                        'malicious_count': scan_result['malicious_count'],
                        'total_count': scan_result['total_count'],
                        'permalink': scan_result['permalink']
                    })
                    malicious_report += f"URL: {url}\nMalicious Reports: {scan_result['malicious_count']}/{scan_result['total_count']}\n\n"
        
        # Check Attachments
        for byte_data, filename in attachments:
            scan_result = check_file_virustotal(byte_data, filename)
            if scan_result:
                findings.append({
                    'type': 'Attachment',
                    'value': filename,
                    'details': scan_result['details'],
                    'malicious_count': scan_result['malicious_count'],
                    'total_count': scan_result['total_count'],
                    'permalink': scan_result['permalink']
                })
                malicious_report += f"Attachment: {filename}\nMalicious Reports: {scan_result['malicious_count']}/{scan_result['total_count']}\n\n"

        # Mark the email as unread after processing
        mark_as_unread(mail, email_id)
        
        return malicious_report, sender, subject, findings

    except Exception as e:
        logging.error(f"Failed to process email ID {email_id}: {e}")
        return "", None, None, None

def mark_as_unread(mail, email_id):
    """Mark the email as unread by removing the SEEN flag."""
    try:
        mail.store(email_id, '-FLAGS', '\\Seen')
        logging.info(f"Marked email ID {email_id} as unread.")
    except Exception as e:
        logging.error(f"Failed to mark email ID {email_id} as unread: {e}")

def generate_severity_graphic(malicious_count, total_count):
    """Generate a visually appealing bar graphic to represent the severity of findings."""
    width = 300
    height = 50
    bar_length = int((malicious_count / total_count) * width)
    
    # Create the image
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)

    # Draw the severity bar with gradient color
    draw.rectangle([0, 0, bar_length, height], fill='red')
    draw.rectangle([bar_length, 0, width, height], fill='lightgrey')

    # Save to a bytes buffer
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    img_str = b64encode(buffered.getvalue()).decode()
    return img_str  # Return the base64-encoded image string

def send_report(sender, subject, findings):
    """Send the report via email securely."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = EMAIL_ADDRESS
        msg['Subject'] = REPORT_EMAIL_TITLE
        
        # Build the HTML report
        html_template = """
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333; margin: 0; padding: 20px; background-color: #f4f4f9; }}
                h2, h3 {{ color: #2e6da4; }}
                .report-section {{ background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-bottom: 20px; text-align: center; }}
                .severity-bar img {{ max-width: 100%; height: auto; }}
                .redirect-button {{ background-color: #2e6da4; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-top: 10px; text-decoration: none; display: inline-block; }}
                .redirect-button:hover {{ background-color: #204d74; }}
                .footer {{ font-size: 0.8em; color: #666; text-align: center; margin-top: 20px; }}
                .bar-caption {{ text-align: center; margin-top: 10px; font-size: 0.9em; color: #555; }}
                .url-text {{ word-wrap: break-word; font-size: 0.9em; color: #2e6da4; }}
            </style>
        </head>
        <body>
            <h2>Malicious URL and Attachment Scan Report</h2>
            <p><strong>Sender:</strong> {sender}</p>
            <p><strong>Subject:</strong> {subject}</p>
            <hr>
            {findings_html}
            <div class="footer">
                <p>Generated by VirusTotal Scanner</p>
            </div>
        </body>
        </html>
        """
        
        findings_html = ""
        for i, finding in enumerate(findings, start=1):
            graphic = generate_severity_graphic(finding['malicious_count'], finding['total_count'])
            findings_html += f"""
            <div class="report-section">
                <h3>Dangerous Content Detected!</h3>
                <div class="severity-bar">
                    <img src="data:image/png;base64,{graphic}" alt="Severity Bar">
                </div>
                <div class="bar-caption">{finding['malicious_count']}/{finding['total_count']} flagged this as malicious</div>
            """
            if finding['type'] == 'URL':
                findings_html += f"""
                <p class="url-text"><strong>MALICIOUS URL (don't click it!):</strong> <span>{escape(finding['value'])}</span></p>
                <a class="redirect-button" href="{finding['permalink']}" target="_blank">View on VirusTotal</a>
                """
            elif finding['type'] == 'Attachment':
                findings_html += f"""
                <h3>Malicious Attachment</h3>
                <p class="url-text"><strong>Name:</strong> <span>{escape(finding['value'])}</span></p>
                <a class="redirect-button" href="{finding['permalink']}" target="_blank">View on VirusTotal</a>
                """
            findings_html += "</div>"
        
        # Fill in the template with actual data
        try:
            html_content = html_template.format(sender=escape(sender), subject=escape(subject), findings_html=findings_html)
        except KeyError as ke:
            logging.error(f"Key error in HTML formatting: {ke}")
            return

        # Log the generated HTML content for debugging
        logging.debug(f"Generated HTML content:\n{html_content}")

        msg.attach(MIMEText(html_content, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, EMAIL_ADDRESS, text)
        server.quit()
        logging.info("Report sent successfully.")
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send report: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during email sending: {e}")
        raise



def main():
    try:
        mail = access_email()
        email_ids = fetch_unread_emails(mail)
        
        if not email_ids:
            logging.info("No new emails found.")
            return

        # Load the list of processed email IDs
        processed_emails = load_processed_emails()

        for email_id in email_ids:
            email_id_str = email_id.decode()  # Convert bytes to string for comparison
            if email_id_str not in processed_emails:
                malicious_report, sender, subject, findings = process_email(email_id, mail)
                if malicious_report:
                    send_report(sender, subject, findings)
                # Save the email ID after processing
                save_processed_email(email_id_str)
            else:
                logging.info(f"Skipping already processed email ID {email_id_str}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
