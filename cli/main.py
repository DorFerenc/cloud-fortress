# Entry point to run the scan
# from app.data.sample_env import setup_mock_s3_environment
# from app.core.aws_connector import get_s3_client
# from app.services.s3_scanner import scan_s3_buckets
# from app.interface.json_interface import generate_report
import argparse

import sys
import os

# Add the parent directory of the current script to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.sample_env import setup_mock_s3_environment, setup_mock_iam_environment, setup_mock_ec2_environment
from app.core.aws_connector import get_s3_client
from app.services.s3_scanner import scan_s3_buckets
from app.services.iam_scanner import scan_iam_roles
from app.services.ec2_scanner import scan_ec2_instances
from app.services.sg_scanner import scan_security_groups
from app.interface.json_interface import generate_report
from cli.send_report import send_report

def main(send=False):
    print("[*] Setting up simulated environment...")
    mock = setup_mock_s3_environment()
    mock_s3 = setup_mock_s3_environment()
    mock_iam = setup_mock_iam_environment()
    mock_ec2 = setup_mock_ec2_environment()

    print("[*] Connecting to fake AWS...")
    s3_client = get_s3_client()

    print("[*] Scanning S3 buckets...")
    s3_findings = scan_s3_buckets(s3_client)
    print("[*] Scanning IAM roles...")
    iam_findings = scan_iam_roles()
    print("[*] Scanning EC2 instances...")
    ec2_findings = scan_ec2_instances()
    print("[*] Scanning security groups...")
    sg_findings = scan_security_groups()

    print("[*] Generating report...")
    generate_report(s3_findings, iam_findings, ec2_findings, sg_findings)

    if send:
        print("[*] Sending report to dashboard...")
        send_report()

    print("[*] Done.")
    mock.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CNAPP-lite S3 Scanner")
    parser.add_argument('--send', action='store_true', help="Send results to dashboard API")
    args = parser.parse_args()
    main(send=args.send)
