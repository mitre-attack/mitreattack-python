# Diff Stix

This folder contains a module for creating markdown, HTML, JSON and/or ATT&CK Navigator layers
reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content.
Run `diff_stix -h` for full usage instructions.

## Usage

### Command Line

Print full usage instructions:

```shell
# You must run `pip install mitreattack-python` in order to access the diff_stix command
diff_stix --help
usage: diff_stix [-h] [--old OLD] [--new NEW] [--domains {enterprise-attack,mobile-attack,ics-attack} [{enterprise-attack,mobile-attack,ics-attack} ...]] [--markdown-file MARKDOWN_FILE] [--html-file HTML_FILE] [--html-file-detailed HTML_FILE_DETAILED]
                 [--json-file JSON_FILE] [--layers [LAYERS ...]] [--site_prefix SITE_PREFIX] [--unchanged] [--use-mitre-cti] [--show-key] [--contributors] [--no-contributors] [-v]

Create changelog reports on the differences between two versions of the ATT&CK content. Takes STIX bundles as input. For default operation, put enterprise-attack.json, mobile-attack.json, and ics-attack.json bundles in 'old' and 'new' folders for the script to compare.

options:
  -h, --help            show this help message and exit
  --old OLD             Directory to load old STIX data from.
  --new NEW             Directory to load new STIX data from.
  --domains {enterprise-attack,mobile-attack,ics-attack} [{enterprise-attack,mobile-attack,ics-attack} ...]
                        Which domains to report on. Choices (and defaults) are enterprise-attack, mobile-attack, ics-attack
  --markdown-file MARKDOWN_FILE
                        Create a markdown file reporting changes.
  --html-file HTML_FILE
                        Create HTML page from markdown content.
  --html-file-detailed HTML_FILE_DETAILED
                        Create an HTML file reporting detailed changes.
  --json-file JSON_FILE
                        Create a JSON file reporting changes.
  --layers [LAYERS ...]
                        Create layer files showing changes in each domain expected order of filenames is 'enterprise', 'mobile', 'ics', 'pre attack'. If values are unspecified, defaults to output/January_2023_Updates_Enterprise.json,
                        output/January_2023_Updates_Mobile.json, output/January_2023_Updates_ICS.json, output/January_2023_Updates_Pre.json
  --site_prefix SITE_PREFIX
                        Prefix links in markdown output, e.g. [prefix]/techniques/T1484
  --unchanged           Show objects without changes in the markdown output
  --use-mitre-cti       Use content from the MITRE CTI repo for the -old data
  --show-key            Add a key explaining the change types to the markdown
  --contributors        Show new contributors between releases
  --no-contributors     Do not show new contributors between releases
  -v, --verbose         Print status messages
```

Example execution:

```shell
diff_stix -v --show-key --html-file output/changelog.html --html-file-detailed output/changelog-detailed.html --markdown-file output/changelog.md  --json-file output/changelog.json --layers output/layer-enterprise.json output/layer-mobile.json output/layer-ics.json --old path/to/old/stix/ --new path/to/new/stix/
```
