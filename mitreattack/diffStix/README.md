# Diff Stix

This folder contains a module for creating markdown, HTML, JSON and/or ATT&CK Navigator layers
reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content.
Run `diff_stix -h` for full usage instructions.

## Usage

### Command Line

Print full usage instructions:

```shell
python3 changelog_helper.py -h
```

Example execution:

```shell
python3 changelog_helper.py -v --use-mitre-cti -new path/to/new/stix/ --minor-changes --show-key --create-html --contributors -markdown output/changelog.md -json-output output/changelog.json -layers output/layer-enterprise.json output/layer-mobile.json
```
