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

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Step 1: Accessing Email
def access_email():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select('inbox')
        logging.info("Email login successful.")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to login to email: {e}")
        raise

# Step 2: Reading New Emails
def fetch_unread_emails(mail):
    try:
        status, messages = mail.search(None, '(UNSEEN)')
        email_ids = messages[0].split()
        logging.info(f"Found {len(email_ids)} unread emails.")
        return email_ids
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to fetch unread emails: {e}")
        raise

# Step 3: Extracting Links
def extract_links(email_body):
    urls = re.findall(r'(https?://[^\s]+)', email_body)
    logging.info(f"Extracted {len(urls)} URLs.")
    return urls

# Step 4: Checking Links on VirusTotal
def check_links_virustotal(urls):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    results = {}
    for url in urls:
        try:
            response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url}
            )
            response.raise_for_status()  # Raises an HTTPError for bad responses

            analysis_id = response.json().get('data', {}).get('id')
            if analysis_id:
                analysis_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers
                )
                analysis_response.raise_for_status()  # Raises an HTTPError for bad responses
                
                result = analysis_response.json()
                malicious_count = result['data']['attributes']['stats']['malicious']
                results[url] = malicious_count
                logging.info(f"Checked URL {url}: {malicious_count} malicious reports.")
            else:
                results[url] = "Error: Submission failed"
                logging.warning(f"Submission failed for URL: {url}")
        except RequestException as e:
            results[url] = f"Error: Unable to check - {str(e)}"
            logging.error(f"Request failed for URL {url}: {e}")
    return results

# Step 5: Sending the Report
def send_report(report):
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

# Main Function
def main():
    try:
        mail = access_email()
        email_ids = fetch_unread_emails(mail)
        
        if not email_ids:
            logging.info("No new emails found.")
            return

        malicious_report = ""
        for email_id in email_ids:
            status, data = mail.fetch(email_id, '(RFC822)')
            msg = email.message_from_bytes(data[0][1])
            email_body = msg.get_payload(decode=True).decode()
            
            urls = extract_links(email_body)
            if urls:
                virustotal_results = check_links_virustotal(urls)
                for url, malicious_count in virustotal_results.items():
                    if isinstance(malicious_count, int) and malicious_count > 0:
                        malicious_report += f"URL: {url}\nMalicious Reports: {malicious_count}\n\n"

        if malicious_report:
            send_report(malicious_report)
            logging.info("Malicious URLs detected and report sent.")
        else:
            logging.info("No malicious URLs found.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
