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

The `-old` and `-new` flags should point to folders.
Each folder should have 3 files in it from a specific version of the released ATT&CK STIX 2.0 data found at <https://github.com/mitre/cti>:

* `enterprise-attack.json`
* `mobile-attack.json`
* `ics-attack.json`

Example execution:

```shell
python3 changelog_helper.py -v --show-key --markdown-file output/changelog.md --html-file output/changelog.html --html-file-detailed output/changelog-detailed.html --json-file output/changelog.json -layers output/layer-enterprise.json output/layer-mobile.json output/layer-ics.json -old path/to/old/stix/ -new path/to/old/stix/
```
