# Brainwave_Matrix_Intern
# URL Scanner

This Python script checks a given URL for validity, determines the domain's age using WHOIS, and scans the URL for malicious or suspicious activity using the VirusTotal API.

## Features

- **URL Validation:** Ensures the input is a valid URL.
- **Domain Age Check:** Uses WHOIS to determine how old the domain is.
- **VirusTotal Scan:** Checks the URL against VirusTotal for malicious or suspicious reports.

## Requirements

- Python 3.x
- [validators](https://pypi.org/project/validators/)
- [python-whois](https://pypi.org/project/python-whois/)
- [vt-py](https://pypi.org/project/vt-py/)

Install dependencies with:

```sh
pip install validators python-whois vt-py
```

## Usage

1. Replace the `VT_API_KEY` variable in [`Task-1.py`](Task-1.py) with your own VirusTotal API key.
2. Run the script:

```sh
python Task-1.py
```

3. Enter the URL you want to scan when prompted.

## Output

- Displays the domain age in days.
- Warns if the domain is newly registered (under 90 days).
- Shows VirusTotal results: number of malicious and suspicious detections.
- Flags if the URL is considered malicious or suspicious.

## Notes

- Ensure you have a valid VirusTotal API key.
- WHOIS lookups may fail for some domains or TLDs.

## License

This project is for educational purposes.
