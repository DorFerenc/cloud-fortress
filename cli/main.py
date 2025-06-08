# Entry point to run the scan
import argparse, sys, os, logging
from datetime import datetime
from dotenv import load_dotenv
import json

# Ensure our top‐level package is importable
# This is necessary to allow relative imports to work correctly
# Add the parent directory of the current script to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# AWS & scanning imports
from app.data.sample_env import setup_mock_s3_environment, setup_mock_iam_environment, setup_mock_ec2_environment
from app.core.aws_connector import get_aws_clients
from app.services.s3_scanner import scan_s3_buckets
from app.services.iam_scanner import scan_iam_roles
from app.services.ec2_scanner import scan_ec2_instances
from app.services.sg_scanner import scan_security_groups
from app.interface.json_interface import generate_report
from app.core.aws_build_scenario import build_demo_resources

# Diff & send imports
from cli.diff_report import build_partial_report, load_report, build_diff_payload
from cli.send_report import send_report, send_report_diff


# ————— Environment & logging —————
LAST_SCAN_FILE = "last_scan-"
CURRENT_SCAN_FILE = "current_scan-"
CURRENT_DELTA_SCAN_FILE = "current_delta_scan_results-"
CURRENT_PARTIAL_SCAN_FILE = "current_partial_delta_scan_results-"

# load env before boto3 ever runs
# load_dotenv('cloudfortress.env', override=True)   # <— move to very top / keep here
# Load .env early so it's available for everything
def load_environment():
    load_dotenv('cloudfortress.env', override=True)
    load_dotenv()
    return (
        os.getenv("PRODUCT_ID", "default-prod-id"),
        os.getenv("PROJECT_ID", "default-proj-id"),
        os.getenv("REPORT_URL"),
        os.getenv("AWS_CREDENTIALS_JSON")
    )

# Configure logging
def setup_logging():
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

# ————— File I/O helpers —————

def write_report(report_name, report_data, username):
    """
    Write the full scan report for this user to disk.
    """
    scan_result_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    os.makedirs(scan_result_path, exist_ok=True)
    file_path = os.path.join(scan_result_path, f"{report_name}{username}.json")
    with open(file_path, "w") as file:
        json.dump(report_data, file, indent=4)
    print(f"[+] Report written to {file_path}")
    return file_path

# ————— Per‐user scan logic —————

def scan_user(user_index, num_users, mode, build, product_id, project_id, report_url, creds_json, send):
    mock_objs = []
    aws_clients = {}
    try:
        # 1) Setup AWS environment (mock or real)
        if mode == "mock":
            logging.info("[*] Setting up simulated (fake) environment...")
            mock_objs = [
                setup_mock_s3_environment(),
                setup_mock_iam_environment(),
                setup_mock_ec2_environment()
            ]
        elif mode == "real":
            logging.info("[*] Connecting to real AWS environment...")

        # Pass user_index to get_aws_clients
        aws_clients = get_aws_clients(os.getenv("AWS_DEFAULT_REGION"), mode, user_index=user_index)

        if mode == "real" and build:
            build_demo_resources(aws_clients)

        # 2) Run all scanners
        s3_findings  = scan_s3_buckets(aws_clients['s3'])
        iam_findings = scan_iam_roles(aws_clients['iam'])
        ec2_findings = scan_ec2_instances(aws_clients['ec2'])
        sg_findings  = scan_security_groups(aws_clients['ec2'])
        username = aws_clients['username']

        if product_id == "default-prod-id" or project_id == "default-proj-id":
            logging.error("[!] ERROR: .env file not loaded or missing keys.")

        logging.info(f"[*] Generating report for user {user_index+1}/{num_users} ({username})...")

        # 3) Generate full report in‐memory
        report_data = generate_report(
            s3_findings=s3_findings,
            iam_findings=iam_findings,
            ec2_findings=ec2_findings,
            sg_findings=sg_findings,
            username=username,
            PRODUCT_ID=product_id,
            PROJECT_ID=project_id
        )

        # 4) Write new full report to disk
        new_path = write_report(CURRENT_SCAN_FILE, report_data, username)

        # 5) Load old & new, compute diff
        base     = os.path.dirname(new_path)
        old_path = os.path.join(base, f"{LAST_SCAN_FILE}{username}.json")
        old      = load_report(old_path)
        new      = load_report(new_path)


        # 6) Build diff and send. If there *is* any change, send diff and update cache
        delta    = build_diff_payload(old, new)
        write_report(CURRENT_DELTA_SCAN_FILE, delta, username)

        if any(delta[sect]["added"] or delta[sect]["removed"] or delta[sect]["modified"]
               for sect in ("assets", "meta-data", "alerts")):

            # Build the partial report in the normal template:
            partial = build_partial_report(new, delta)
            write_report(CURRENT_PARTIAL_SCAN_FILE, partial, username)

            if send:
                logging.info("[*] Sending diff to dashboard...")
                # send_report_diff(delta, report_url)
                send_report_diff(partial, report_url)

            # overwrite cache with the new full report for next run
            write_report(LAST_SCAN_FILE, new, username)
        else:
            logging.info("[*] No changes since last scan; nothing to send.")

    except Exception:
        logging.exception("[!] Scan failed with exception")
        logging.error("[!] Please check the logs for more details.", exc_info=True)
    finally:
        # Cleanup moto mocks & clients
        for m in mock_objs:
            try:
                m.stop()
            except Exception:
                pass
        for client in aws_clients.values():
            try:
                client.close()
            except Exception:
                pass
        logging.info("[*] Cleanup complete.")

# ————— CLI argument parsing & entrypoint —————

def parse_args():
    # Add more arguments here as needed, e.g.:
    # parser.add_argument('--profile', type=str, help="AWS profile to use")
    parser = argparse.ArgumentParser(
        description="CNAPP-lite Cloud Security Scanner"
    )
    parser.add_argument('--send', action='store_true', help="Send results to dashboard API")
    parser.add_argument('--mode', choices=['mock', 'real'], default='mock', help="mock = moto (default), real = live AWS account")
    parser.add_argument('--build', action='store_true', help="Create demo AWS resources")
    return parser.parse_args()

def main():
    args = parse_args()
    product_id, project_id, report_url, creds_json = load_environment()
    setup_logging()

    # Determine number of users from AWS_CREDENTIALS_JSON if provided
    num_users = 1
    if creds_json:
        try:
            creds = json.loads(creds_json)
            if isinstance(creds, list):
                num_users = len(creds)
        except Exception as e:
            logging.error(f"Failed to parse AWS_CREDENTIALS_JSON: {e}")

    # Scan for each user/credential set
    for user_index in range(num_users):
        scan_user(
            user_index=user_index,
            num_users=num_users,
            mode=args.mode,
            build=args.build,
            product_id=product_id,
            project_id=project_id,
            report_url=report_url,
            creds_json=creds_json,
            send=args.send
        )

if __name__ == "__main__":
    main()
