# Python Scripts

Planned home for Python automation: API integrations, log parsers, reporting and glue code.

Suggested categories (create the folder when the first script is added):

- `monitoring/` — checks and exporters
- `network/` — DNS, IP/GeoIP, port scans
- `database/` — DB reporting
- `cloud/` — provider API clients
- `tools/` — generators and converters

Conventions:

- Python 3, files in `snake_case.py`.
- Use `argparse`, a `main()` function and `if __name__ == "__main__":`.
- List third-party dependencies in a `requirements.txt` in the category folder.
