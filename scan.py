import os
import imaplib
import email
import re
import requests
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
from requests.exceptions import RequestException
from html import escape
from bs4 import BeautifulSoup

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

# Set up logging
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
    """Access and login to the email server."""
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
    """Fetch unread emails from the inbox."""
    try:
        status, messages = mail.search(None, '(UNSEEN)')
        email_ids = messages[0].split()
        logging.info(f"Found {len(email_ids)} unread emails.")
        return email_ids
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to fetch unread emails: {e}")
        raise

def extract_links(email_body):
    """Extract and clean URLs from the email body."""
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
    # Decode HTML entities and remove extra HTML characters
    clean_url = url.split('&')[0]  # This removes trailing parameters after '&'
    clean_url = clean_url.split('"')[0]  # This removes trailing characters after '"'
    clean_url = clean_url.split('<')[0]  # This removes trailing characters after '<'
    clean_url = clean_url.split('>')[0]  # This removes trailing characters after '>'
    return clean_url.strip()

def check_link_virustotal(url):
    """Check a single URL on VirusTotal and return the malicious count."""
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    try:
        # Step 1: Submit the URL for analysis
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url}
        )
        response.raise_for_status()
        
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            logging.warning(f"Submission failed for URL: {url}")
            return "Error: Submission failed"
        
        # Step 2: Polling to get the analysis results
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        for attempt in range(5):  # Retry up to 5 times with delays
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                result = analysis_response.json()
                status = result.get('data', {}).get('attributes', {}).get('status')
                
                if status == "completed":
                    # Extract the malicious count
                    malicious_count = result['data']['attributes']['stats']['malicious']
                    logging.info(f"Checked URL {url}: {malicious_count} malicious reports.")
                    return malicious_count
                
                logging.info(f"Waiting for analysis results for URL {url}... attempt {attempt + 1}")
                time.sleep(5)  # Wait for 5 seconds before the next poll
            else:
                logging.error(f"Error fetching analysis results for URL {url}: {analysis_response.status_code}")
                break
        
        logging.warning(f"Analysis not completed for URL: {url} after multiple attempts.")
        return "Error: Analysis not completed"

    except RequestException as e:
        logging.error(f"Request failed for URL {url}: {e}")
        return f"Error: Unable to check - {str(e)}"


def send_report(report):
    """Send the report via email."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = EMAIL_ADDRESS
        msg['Subject'] = 'Malicious URLs Detected in Recent Emails'
        
        body = 'Malicious URL Scan Report:\n\n' + report
        msg.attach(MIMEText(body, 'plain'))
        
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

def process_email(email_id, mail):
    """Process a single email to extract and check URLs."""
    try:
        status, data = mail.fetch(email_id, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])
        email_body = None

        if msg.is_multipart():
            # If the email is multipart, extract the payloads
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Check if the content is text/plain or text/html and not an attachment
                if "attachment" not in content_disposition:
                    if content_type == "text/plain":
                        email_body = part.get_payload(decode=True).decode()
                        break  # Use the plain text version if available
                    elif content_type == "text/html" and not email_body:
                        email_body = part.get_payload(decode=True).decode()
        else:
            # Non-multipart message, directly get the payload
            email_body = msg.get_payload(decode=True).decode()

        if not email_body:
            logging.warning(f"No suitable content found in email ID {email_id}.")
            return ""

        urls = extract_links(email_body)
        malicious_report = ""
        if urls:
            for url in urls:
                malicious_count = check_link_virustotal(url)
                if isinstance(malicious_count, int) and malicious_count > 0:
                    malicious_report += f"URL: {url}\nMalicious Reports: {malicious_count}\n\n"

        # Mark the email as unread after processing
        mark_as_unread(mail, email_id)
        
        return malicious_report

    except Exception as e:
        logging.error(f"Failed to process email ID {email_id}: {e}")
        return ""

def mark_as_unread(mail, email_id):
    """Mark the email as unread by removing the SEEN flag."""
    try:
        mail.store(email_id, '-FLAGS', '\\Seen')
        logging.info(f"Marked email ID {email_id} as unread.")
    except Exception as e:
        logging.error(f"Failed to mark email ID {email_id} as unread: {e}")

def main():
    try:
        mail = access_email()
        email_ids = fetch_unread_emails(mail)
        
        if not email_ids:
            logging.info("No new emails found.")
            return

        # Load the list of processed email IDs
        processed_emails = load_processed_emails()

        overall_report = ""
        for email_id in email_ids:
            email_id_str = email_id.decode()  # Convert bytes to string for comparison
            if email_id_str not in processed_emails:
                malicious_report = process_email(email_id, mail)
                if malicious_report:
                    overall_report += malicious_report
                # Save the email ID after processing
                save_processed_email(email_id_str)
            else:
                logging.info(f"Skipping already processed email ID {email_id_str}")

        if overall_report:
            send_report(overall_report)
            logging.info("Malicious URLs detected and report sent.")
        else:
            logging.info("No malicious URLs found.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
