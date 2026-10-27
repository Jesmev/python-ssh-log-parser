import argparse
from collections import Counter
import re
import sys


class AuthLogParser:
    def __init__(self, log_path: str):
        self.log_path = log_path
        # Regex to capture username and IP address on failed attempts
        self.failed_pattern = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
        )

    def parse(self):
        failed_ips = Counter()
        total_failed_attempts = 0

        try:
            with open(self.log_path, "r") as file:
                for line in file:
                    match = self.failed_pattern.search(line)
                    if match:
                        username = match.group(1)
                        ip_address = match.group(2)
                        failed_ips[ip_address] += 1
                        total_failed_attempts += 1
                        print(f"Alert: Failed login for '{username}' from IP {ip_address}")

            self._print_summary(total_failed_attempts, failed_ips)

        except FileNotFoundError:
            print(f"Error: The file '{self.log_path}' could not be found.", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied when trying to read '{self.log_path}'.", file=sys.stderr)
            sys.exit(1)

    def _print_summary(self, total: int, ips: Counter):
        print("\n" + "=" * 30)
        print("SECURITY LOG PARSER SUMMARY")
        print("=" * 30)
        print(f"Total failed login attempts: {total}")
        print("\nTop Attacking IP Addresses:")
        # most_common(3) pulls the top 3 most frequent IPs
        for ip, count in ips.most_common(3):
            print(f"  - {ip}: {count} attempts")
        print("=" * 30)


def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Parse SSH authentication logs for failed login attempts.")
    parser.add_argument(
        "-f", "--file", 
        default="sample_auth.log", 
        help="Path to the auth log file (default: sample_auth.log)"
    )
    
    args = parser.parse_args()

    print(f"--- Analyzing log file: {args.file} ---")
    log_parser = AuthLogParser(args.file)
    log_parser.parse()


if __name__ == "__main__":
    main()