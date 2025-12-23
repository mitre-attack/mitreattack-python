# Examples Directory

This directory contains example scripts demonstrating how to use the [`mitreattack-python`](https://github.com/mitre-attack/mitreattack-python)
library to extract, analyze, and report on MITRE ATT&CK data.
These scripts cover a variety of use cases, including querying STIX bundles, generating reports, and automating ATT&CK data analysis.

## Full Example Listing & Documentation

A complete, categorized list of example scripts, usage details, and direct links is maintained in the built documentation:

- [mitreattack-python Examples Documentation](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/examples.html)

## Setup

Many example scripts allow optional configuration via environment variables for paths to STIX bundles.
If you want to set this up you can follow these instructions.

- Copy the provided [`examples/.env.example`](examples/.env.example:1) file to `.env`:

  ```sh
  cp .env.example .env
  ```

- Edit `.env` to set the correct paths and variables for your environment.

Creating a .env file is not enough however. You will need to use a tool such as the following to help manage the environment variables:

- [`python-dotenv`](https://pypi.org/project/python-dotenv/) (automatically loads `.env` in Python scripts)
- [`direnv`](https://direnv.net/) (manages environment variables per directory)

Setting up these tools is out of scope for this README.

### Dependencies

- [`mitreattack-python`](https://github.com/mitre-attack/mitreattack-python)
- Python 3.x
- ATT&CK STIX bundles

### Downloading ATT&CK STIX Bundles

Many example scripts require ATT&CK STIX bundles, which must be downloaded and placed in the directory specified in your `.env` file (e.g., `attack-releases/stix-2.0/v18.0`).
You can download these bundles using the provided CLI command if you have mitreattack-python installed:

```sh
download_attack_stix --all
```

This will download all available ATT&CK releases in STIX format to the default directory (`attack-releases`).
You can customize the download location and versions using additional options. For example:

- Download the latest release (default):

  ```sh
  download_attack_stix
  ```

- Download specific versions:

  ```sh
  download_attack_stix -v 16.1 -v 17.1
  ```

- Download all releases in both STIX formats:

  ```sh
  download_attack_stix --all --stix21
  ```

## How to Run Scripts

- Run individual scripts with Python:

  ```sh
  python get_all_techniques.py
  ```

## Contribution & Customization

Feel free to adapt these scripts for your own use cases. Contributions and improvements are welcome!
