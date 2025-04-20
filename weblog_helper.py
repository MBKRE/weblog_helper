import argparse
import ipaddress
import re
import sys
import logging

# Set up a global logger
logger = logging.getLogger("IPChecker")

def configure_logger(debug=False):
    """Configure logging format and level."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def validate_input_ip(ip_addr):
    """Validate and return an ip_network object (CIDR or single IP)."""
    try:
        network = ipaddress.ip_network(ip_addr, strict=False)
        logger.debug(f"Validated IP/network: {network}")
        return network
    except ValueError:
        logger.error(f"Invalid IP or CIDR format: {ip_addr}")
        return None

def check_logs_for_ip(check_ip):
    """Scan 'public_access.log.txt' and print lines matching the given IP or range."""
    is_ip_present = False
    try:
        with open('public_access.log.txt', 'r') as log:
            for line in log:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    line_ip = match.group(1)
                    try:
                        if ipaddress.ip_address(line_ip) in check_ip:
                            logger.info(f"Match: {line.strip()}")
                            is_ip_present = True
                    except ValueError:
                        logger.warning(f"Skipping invalid IP in log: {line_ip}")
                        continue
        if not is_ip_present:
            logger.info(f"No records found for {check_ip}")
    except FileNotFoundError:
        logger.error("Log file 'public_access.log.txt' not found.")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='weblog_helper.py',
        description='Filter entries from "public_access.log.txt" by a given IP address or CIDR range.',
        epilog='Examples:\n'
               '  python weblog_helper.py --ip 192.168.1.1\n'
               '  python weblog_helper.py --ip 10.0.0.0/24 --debug',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '--ip', '-i',
        required=True,
        help='IP address or CIDR range to search for (e.g. 192.168.0.1 or 10.0.0.0/24)'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode for detailed logs.'
    )

    args = parser.parse_args()

    configure_logger(debug=args.debug)

    ip_filter = validate_input_ip(args.ip)
    if ip_filter:
        check_logs_for_ip(ip_filter)
