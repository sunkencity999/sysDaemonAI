#!/usr/bin/env python3
import argparse
import sys
from license_manager import LicenseManager
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description='SysDaemon AI License Manager')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    parser.add_argument('--help', action='help', help='Show this help message and exit')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate a new license key')
    generate_parser.add_argument('--tier', choices=['individual', 'professional', 'enterprise', 'administrator'],
                               required=True, help='License tier')
    generate_parser.add_argument('--duration', type=int, required=True,
                               help='License duration in days')

    # Install command
    install_parser = subparsers.add_parser('install', help='Install a license key')
    install_parser.add_argument('license_key', help='License key to install')

    # Validate command
    subparsers.add_parser('validate', help='Validate current license')

    # Info command
    subparsers.add_parser('info', help='Show current license information')

    args = parser.parse_args()
    
    license_manager = LicenseManager()

    if args.command == 'generate':
        try:
            license_key = license_manager.generate_license_key(args.tier, args.duration)
            print(f"\nGenerated License Key:\n{license_key}\n")
            print("Instructions:")
            print("1. Share this license key with your customer")
            print("2. Customer should run: python license_cli.py install <license_key>")
        except Exception as e:
            if "Invalid tier" in str(e):
                print("Error: Invalid tier specified. Available tiers: individual, professional, enterprise, administrator.", file=sys.stderr)
            else:
                print(f"Error generating license: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'install':
        try:
            result = license_manager.install_license(args.license_key)
            if result['status'] == 'success':
                print("\nLicense installed successfully!")
                info = license_manager.get_license_info()
                if info and info['valid']:
                    print(f"Tier: {info['tier']}")
                    print(f"Expires: {info['expires_at']}")
            else:
                print(f"\nError: {result['message']}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error installing license: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'validate':
        try:
            result = license_manager.validate_license()
            if result['valid']:
                print("\nLicense is valid!")
                print(f"Tier: {result['tier']}")
                print(f"Expires: {result['expires_at']}")
            else:
                print(f"\nLicense is invalid: {result.get('error', 'Unknown error')}", file=sys.stderr)
                print("Please run the install command with a valid license key:")
                print("python license_cli.py install <your-license-key>")
                sys.exit(1)
        except Exception as e:
            print(f"Error validating license: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'info':
        try:
            info = license_manager.get_license_info()
            if info and info['valid']:
                print("\nCurrent License Information:")
                print(f"Tier: {info['tier']}")
                print(f"Expires: {info['expires_at']}")
            else:
                print("\nNo valid license found", file=sys.stderr)
                print("Please run the install command with a valid license key:")
                print("python license_cli.py install <your-license-key>")
                sys.exit(1)
        except Exception as e:
            print(f"Error getting license info: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
