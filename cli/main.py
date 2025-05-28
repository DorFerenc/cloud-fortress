# Entry point to run the scan
import argparse
import sys
import os
from dotenv import load_dotenv
import logging
from datetime import datetime

# Add the parent directory of the current script to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.sample_env import setup_mock_s3_environment, setup_mock_iam_environment, setup_mock_ec2_environment
from app.core.aws_connector import get_aws_clients
from app.services.s3_scanner import scan_s3_buckets
from app.services.iam_scanner import scan_iam_roles
from app.services.ec2_scanner import scan_ec2_instances
from app.services.sg_scanner import scan_security_groups
from app.interface.json_interface import generate_report
from cli.send_report import send_report

# Load .env early so it's available for everything
load_dotenv()
PRODUCT_ID = os.getenv("PRODUCT_ID", "default-prod-id")
PROJECT_ID = os.getenv("PROJECT_ID", "default-proj-id")
REPORT_URL =os.getenv("REPORT_URL")

# Configure logging
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)  # Create the logs directory if it doesn't exist
log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d')}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),  # Log to file
        logging.StreamHandler()        # Log to console
    ]
)

def main(send=False):
    print("[*] Setting up simulated environment...")
    mock_s3 = setup_mock_s3_environment()
    mock_iam = setup_mock_iam_environment()
    mock_ec2 = setup_mock_ec2_environment()

    print("[*] Connecting to fake AWS...")
    aws_clients = get_aws_clients()

    print("[*] Scanning S3 buckets...")
    s3_findings = scan_s3_buckets(aws_clients['s3'])
    print("[*] Scanning IAM roles...")
    iam_findings = scan_iam_roles(aws_clients['iam'])
    print("[*] Scanning EC2 instances...")
    ec2_findings = scan_ec2_instances(aws_clients['ec2'])
    print("[*] Scanning security groups...")
    sg_findings = scan_security_groups(aws_clients['sg'])

    if PRODUCT_ID == "default-prod-id" or PROJECT_ID == "default-proj-id":
        print("[!] WARNING: .env file not loaded or missing keys.")

    print("[*] Generating report...")
    generate_report(s3_findings, iam_findings, ec2_findings, sg_findings, PRODUCT_ID, PROJECT_ID)

    if send:
        print("[*] Sending report to dashboard...")
        send_report(url=REPORT_URL )

    print("[*] Done.")
    # Clean up all moto mocks
    mock_s3.stop()
    mock_iam.stop()
    mock_ec2.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CNAPP-lite S3 Scanner")
    parser.add_argument('--send', action='store_true', help="Send results to dashboard API")
    args = parser.parse_args()
    main(send=args.send)
