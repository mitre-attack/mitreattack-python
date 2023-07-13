Diff Stix
==============================================

This folder contains a module for creating markdown, HTML, JSON and/or ATT&CK Navigator layers
reporting on the changes between two versions of the STIX2 bundles representing the ATT&CK content.
Run `diff_stix -h` for full usage instructions.

**Usage**

**Command Line**

Print full usage instructions:

.. code:: bash
# You must run `pip install mitreattack-python` in order to access the diff_stix command
  diff_stix --help
  usage: diff_stix [-h] [--old OLD] [--new NEW] [--domains {enterprise-attack,mobile-attack,ics-attack} [{enterprise-attack,mobile-attack,ics-attack} ...]] [--markdown-file MARKDOWN_FILE] [--html-file         HTML_FILE] [--html-file-detailed HTML_FILE_DETAILED]
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


Example execution:

.. code:: bash
diff_stix -v --show-key --html-file output/changelog.html --html-file-detailed output/changelog-detailed.html --markdown-file output/changelog.md  --json-file output/changelog.json --layers output/layer-enterprise.json output/layer-mobile.json output/layer-ics.json --old path/to/old/stix/ --new path/to/new/stix/


**Changelog JSON format**

The changelog helper script has the option to output a JSON file with detailed differences between ATT&CK releases.
This is the overall structure you can expect to find in the file.
A brief explanation of key pieces can be found below.

.. code-block:: json
  {
    "enterprise-attack": {
      "techniques": {
          "additions": [],
          "major_version_changes": [],
          "minor_version_changes": [],
          "other_version_changes": [],
          "patches": [],
          "revocations": [],
          "deprecations": [],
          "deletions": [],
      },
      "software": {},
      "groups": {},
      "campaigns": {},
      "mitigations": {},
      "datasources": {},
      "datacomponents": {}
    },
    "mobile-attack": {},
    "ics-attack": {},
    "new-contributors": [
      "Contributor A",
      "Contributor B",
      "Contributor C"
    ]
  }


* The top-level objects include information about specific domains as well as `new-contributors`, which are only found in the newer ATT&CK release.
* For domain changes, they are broken down by object type, e.g. `techniques` or `mitigations`.
* The following table helps break down the change types that are currently tracked.

.. list-table:: Title
   :widths: 25 25 50
   :header-rows: 1

   * - field 
     - type
     - description
   * - `additions`     
     -array[object]
     - ATT&CK objects which are only present in the new STIX data.      
   * - `major_version_changes``
     - array[object]
     - ATT&CK objects that have a major version change. (e.g. 1.0 → 2.0). 
   * - `minor_version_changes`
     - array[object]
     - ATT&CK objects that have a minor version change. (e.g. 1.0 → 1.1).  
   * - `other_version_changes`
     - array[object]
     - array[object] | ATT&CK objects that have a version change of any other kind. (e.g. 1.0 → 1.3). These are unintended, but can be found in previous releases.
     * - `patches`     
     - array[object]
     - ATT&CK objects that have been patched while keeping the version the same.  
      * - `revocations`  
     - array[object]
     - ATT&CK objects which are revoked by a different object. 
   * - `deprecations`  
     - array[object]
     - ATT&CK objects which are deprecated and no longer in use, and not replaced.   
   * - `deletions`    
     - array[object
     - ATT&CK objects which are no longer found in the STIX data. This should almost never happen.     


**Changed Objects

The bulk of the changelog file consists of lists of JSON objects.
If you are familiar with reading the STIX format, they may look famliar, yet a little "off".
That is because there are a few fields that have been added in some cases depending on what section they appear in.
For example, objects that are brand new do not have `previous_version` available to them.
The following table lists the extra fields that can be found in objects in the changelog.

.. list-table:: Title
   :widths: 25 25 50
   :header-rows: 1
   
   * - Field
     - Required
     - Type
     - Description
   * - `changelog_mitigations` 
     - false
     - object 
     - Three lists for `shared`, `new`, and `dropped` for Mitigations that are related to a Technique between versions.      
   * - `changelog_detections` 
     - false
     - object 
     - HTML rendering of a table that displays the differences between descriptions for an ATT&CK object.        
   * - `detailed_diff`  
     - false
     - string 
     - A python DeepDiff object that has been JSON serialized which represents STIX changes for an ATT&CK object between releases.        
   * - `previous_version`
     - false
     - string 
     - If the object existed in the previous release, then it denotes the version the object was in the previous release.    
   * - `version_change`  
     - false
     - string 
     - If the object existed in the previous release and was changed in the current release, then a descriptive string in the format '`old-version` → `new-version`' 
                                                    

