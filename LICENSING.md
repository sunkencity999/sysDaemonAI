# SysDaemon AI Licensing Instructions

## For License Administrators

### Setup Environment
```bash
# Create virtual environment
python3 -m venv /path/to/sysDaemonAI/venv

# Activate virtual environment
source /path/to/sysDaemonAI/venv/bin/activate  # For Unix/Mac
# OR
.\venv\Scripts\activate  # For Windows

# Install required packages
pip install cryptography
```

### License Generation and Installation

#### License Generation

Generate licenses using the following command format:
```bash
# Generate a new license key
python license_cli.py generate --tier <tier> --duration <days>
```

Example command with the full path:
```bash
/Users/christopher.bradford/sysDaemonAI/venv/bin/python3 license_cli.py generate --tier professional --duration 365
```

Available tiers:
- individual
- professional
- enterprise
- administrator

Example commands:
```bash
# Generate Individual License (1 year)
python license_cli.py generate --tier individual --duration 365

# Generate Professional License (1 year)
python license_cli.py generate --tier professional --duration 365

# Generate Enterprise License (1 year)
python license_cli.py generate --tier enterprise --duration 365

# Generate Custom Duration License (e.g., 2 years)
python license_cli.py generate --tier professional --duration 730

# Generate Administrator License (lifetime)
python license_cli.py generate --tier administrator --duration 9999
```

#### License Installation

1. Open a terminal in the SysDaemon AI installation directory
2. Run the following command:
```bash
python license_cli.py install <your-license-key>
```

### License Verification

The license key is verified using asymmetric encryption:
- The license is signed with a private key during generation.
- The public key is used for verification during installation.
- If the verification fails, an error message will be displayed.

### Key Management

The keys are automatically generated and managed by the application:
- If the keys do not exist, they will be created in the `keys` directory.
- The private key is used for signing licenses, while the public key is used for verification.

## For End Users

### Client License Manager

The client version of the license manager is available for end users to install their licenses easily:
```bash
/Users/christopher.bradford/sysDaemonAI/venv/bin/python3 client_license_cli.py install <your-license-key>
```

### Checking License Status
```bash
python license_cli.py validate
```

## License Tiers and Pricing

### Individual License
- Price: $199/year
- Features:
  - Full feature set
  - Single machine license
  - Community support

### Professional License
- Price: $499/year
- Features:
  - Multiple machine licenses (up to 5)
  - Priority support
  - Custom rule creation
  - API access

### Enterprise License
- Price: Starting at $2,499/year
- Features:
  - Unlimited machines
  - Custom deployment options
  - Dedicated support
  - Training and consultation
  - Network-wide monitoring

### Administrator License
- Price: Lifetime access
- Features:
  - All features from other tiers
  - Lifetime access

## Purchase a License

Visit [sysDaemonAI.com](https://sysDaemonAI.com) to purchase a license.

## Troubleshooting

### Common Issues

1. **"No module named 'cryptography'"**
   - Solution: Ensure you've activated the virtual environment and installed requirements
   ```bash
   source venv/bin/activate  # Unix/Mac
   pip install cryptography
   ```

2. **"Invalid hardware ID"**
   - Cause: License is tied to a different machine
   - Solution: Purchase a new license for this machine

3. **"License expired"**
   - Solution: Visit [sysDaemonAI.com](https://sysDaemonAI.com) to renew your license

### Support

For additional support:
1. Visit our documentation at [docs.sysDaemonAI.com](https://docs.sysDaemonAI.com)
2. Contact support at [support@sysDaemonAI.com](mailto:support@sysDaemonAI.com)
3. Open an issue on our GitHub repository

## Notes

- Licenses are hardware-locked and cannot be transferred between machines
- Enterprise customers should contact sales for custom licensing options
- All licenses include free updates within the licensed period
