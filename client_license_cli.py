#!/usr/bin/env python3
import argparse
import sys
from license_manager import LicenseManager

def main():
    parser = argparse.ArgumentParser(description='SysDaemon AI Client License Manager')
    parser.add_argument('license_key', help='License key to install')
    args = parser.parse_args()
    
    license_manager = LicenseManager()
    try:
        result = license_manager.install_license(args.license_key)
        if result['status'] == 'success':
            print("License installed successfully!")
            info = license_manager.get_license_info()
            if info and info['valid']:
                print(f"Tier: {info['tier']}")
                print(f"Expires: {info['expires_at']}")
        else:
            print(f"Error: {result['message']}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error installing license: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
