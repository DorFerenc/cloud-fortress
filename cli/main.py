# Entry point to run the scan
import argparse, sys, os, logging
from datetime import datetime
from dotenv import load_dotenv

# Add the parent directory of the current script to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.sample_env import setup_mock_s3_environment, setup_mock_iam_environment, setup_mock_ec2_environment
from app.core.aws_connector import get_aws_clients
from app.services.s3_scanner import scan_s3_buckets
from app.services.iam_scanner import scan_iam_roles
from app.services.ec2_scanner import scan_ec2_instances
from app.services.sg_scanner import scan_security_groups
from app.interface.json_interface import generate_report
from app.core.aws_build_scenario import build_demo_resources

from cli.send_report import send_report


# load env before boto3 ever runs
load_dotenv('cloudfortress.env', override=True)   # <— move to very top / keep here
# Load .env early so it's available for everything
load_dotenv()
PRODUCT_ID = os.getenv("PRODUCT_ID", "default-prod-id")
PROJECT_ID = os.getenv("PROJECT_ID", "default-proj-id")
REPORT_URL = os.getenv("REPORT_URL")

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

def main(send=False, mode="mock", build=False):
    mock_objs = []   # will hold mocks so we can stop() them
    aws_clients = {} # will hold boto3 clients so we can close() them
    try:
        if mode == "mock":
            logging.info("[*] Setting up simulated (fake) environment...")
            mock_objs = [
                setup_mock_s3_environment(),
                setup_mock_iam_environment(),
                setup_mock_ec2_environment()
            ]
        elif mode == "real":
                logging.info("[*] Connecting to real AWS environment...")

        # get real or mock clients
        aws_clients = get_aws_clients(os.getenv("AWS_DEFAULT_REGION"),mode)

        if mode == "real" and build:
            build_demo_resources(aws_clients)

        # --- your scanning steps ---
        s3_findings  = scan_s3_buckets(aws_clients['s3'])
        iam_findings = scan_iam_roles(aws_clients['iam'])
        ec2_findings = scan_ec2_instances(aws_clients['ec2'])
        sg_findings  = scan_security_groups(aws_clients['ec2'])

        if PRODUCT_ID == "default-prod-id" or PROJECT_ID == "default-proj-id":
            logging.error("[!] ERROR: .env file not loaded or missing keys.")

        logging.info("[*] Generating report...")
        generate_report(s3_findings, iam_findings, ec2_findings, sg_findings, aws_clients['username'], PRODUCT_ID, PROJECT_ID)

        if send:
            logging.info("[*] Sending report to dashboard...")
            send_report(url=REPORT_URL)
    except Exception:
        logging.exception("[!] Scan failed with exception")
        logging.error("[!] Please check the logs for more details.", exc_info=True)
    finally:
        # 1. Stop moto mocks (if any)
        for m in mock_objs:
            try:
                m.stop()
            except Exception:
                pass

        # 2. Close boto3 clients to release HTTP pool
        for client in aws_clients.values():
            # botocore clients have a .close() method
            try:
                client.close()
            except Exception:
                pass

        logging.info("[*] Cleanup complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CNAPP-lite Cloud Security Scanner"
    )
    parser.add_argument(
        '--send',
        action='store_true',
        help="Send results to dashboard API"
    )
    parser.add_argument(
        '--mode',
        choices=['mock', 'real'],
        default='mock',
        help="mock = moto (default), real = live AWS account"
    )
    parser.add_argument(
        '--build',
        action='store_true',
        help="Create demo AWS resources"
        )
    # Add more arguments here as needed, e.g.:
    # parser.add_argument('--profile', type=str, help="AWS profile to use")

    args = parser.parse_args()
    main(send=args.send, mode=args.mode, build=args.build)
