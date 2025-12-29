# Roblox Friend Request Bot

A Python tool for sending friend requests on Roblox using multiple accounts with proxy support.

## Features

- Multi-threaded friend request sending
- Proxy rotation support
- CSRF token handling
- Authentication token generation
- Performance tracking and statistics
- Retry mechanism with exponential backoff
- Detailed error reporting

## Requirements

- Python 3.7+
- Required packages (install via `pip install -r requirements.txt`):
  - `curl_cffi`
  - `cryptography`
  - `colorama`

## Setup

1. Clone this repository:
```bash
git clone https://github.com/SpokeOner/friendrequest.git
cd friendrequest
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure your input files:
   - Add your Roblox authentication cookies to `input/cookies.txt` (one per line)
   - Add your proxy addresses to `input/proxies.txt` (one per line, format: `http://user:pass@host:port`)

## Usage

Run the script:
```bash
python friendrequest.py
```

The script will prompt you for:
- Thread count: Number of concurrent threads to use
- User ID: The Roblox user ID to send friend requests to

## Input File Formats

### cookies.txt
Place your Roblox `.ROBLOSECURITY` cookies here, one per line:
```
_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_CAEaAhADIhwKBGR1aWQSFDExNjUzOTY2NTc3NDg1NjA2NzUxKAM...
```

### proxies.txt
Place your proxy addresses here, one per line:
```
http://username:password@proxy.example.com:8080
http://proxy.example.com:8080
```

## Disclaimer

This tool is for educational purposes only. Use responsibly and in accordance with Roblox's Terms of Service.

## License

This project is provided as-is for educational purposes.

## Author

[SpokeOner](https://github.com/SpokeOner)

