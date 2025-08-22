ATT&CK to Java
==============================================

ATT&CK to Java contains a module for converting `ATT&CK STIX data <https://github.com/mitre/cti>`_ to Java class hierarchy.


Usage:
-----

Command Line
-----

Print full usage instructions:

.. code:: bash

    python3 attackToJava.py -h


Example execution:

.. code:: bash

    python3 attackToJava.py -output /tmp/attack


Build a Java files corresponding to a version of ATT&CK:

.. code:: bash

    python3 attackToJava -output /tmp/attack -version v5.0



Interfaces:
-----

attackToJava
-----
attackToJava provides the means by which to convert/extract the ATT&CK STIX data to Java class hierarchy. 
A brief overview of the available methods follows.

.. list-table:: Title
   :widths: 33 33 34
   :header-rows: 1

   * - method name
     - arguments
     - usage
   * - export
     - `domain`: the domain of ATT&CK to download <br> `version`: optional parameter specifying which version of ATT&CK to download <br> `output_dir`: optional parameter specifying output directory
    - `version` : The version of ATT&CK to download, e.g "v8.1". If omitted will build the current version of ATT&CK, by default None
    - `output_dir` : The directory to write the Java files to.
    - `remote` : The URL of a remote ATT&CK Workbench instance to connect to for stix data. Mutually exclusive with stix_file.
    - `stix_file` : Path to a local STIX file containing ATT&CK data for a domain, by default None
    - Download ATT&CK data from MITRE/CTI and convert it to Java class hierarchy

stixToJava
-----

stixToJava provides various methods to process and manipulate the STIX data in order to create Java

.. list-table:: Method Documentation
   :widths: 33 33 34
   :header-rows: 1

   * - method name
     - arguments
     - usage
   * - runMaven
     - `output_dir`: str
     - Run Maven to build the Java classes.<br>`output_dir`: The directory to run Maven in, by default "."
   * - remove_tautology
     - `text`: str
     - Remove tautology from the text.<br>`text`: The text to process.<br>Returns the processed text without tautology.
   * - formatTextToLines
     - `text`: str<br>`max_line_length`: int = 80
     - Format text to lines of a specified maximum length.<br>`text`: The text to format.<br>`max_line_length`: The maximum line length, by default 80.<br>Returns the formatted lines.
   * - buildOutputDir
     - `package_name`: str = None<br>`output_dir`: str = None
     - Build the output directory for the Java classes.<br>`package_name`: The name of the package to create the directory for.<br>`output_dir`: The root directory for output.<br>Returns the path to the output directory.
   * - nameToClassName
     - `name`: str
     - Convert a name to a class name.<br>`name`: The name to convert.<br>Returns the class name.
   * - writeJinja2Template
     - `templateEnv`: jinja2.Environment<br>`template_name`: str<br>`output_file`: str<br>`fields`: dict
     - Write a Jinja2 template to a file.<br>`templateEnv`: The Jinja2 environment.<br>`template_name`: The template file to use.<br>`output_file`: The output file to write to.<br>`fields`: The fields to use in the template.
   * - stixToTactics
     - `stix_data`: MemoryStore<br>`package_name`: str<br>`domain`: str<br>`verbose_class`: bool = False<br>`output_dir`: str = "."
     - Parse STIX tactics from the given data and write corresponding Java classes.<br>`stix_data`: MemoryStore or other stix2 DataSource object holding the domain data.<br>`package_name`: The base package name for the output Java classes.<br>`domain`: The domain of ATT&CK stix_data corresponds to, e.g., "enterprise-attack".<br>`verbose_class`: Whether to include verbose class information, by default False.<br>`output_dir`: The root directory for output, by default ".".
   * - stixToTechniques
     - `all_data_sources`: dict<br>`all_defenses_bypassed`: dict<br>`all_platforms`: dict<br>`stix_data`: MemoryStore<br>`package_name`: str<br>`domain`: str<br>`verbose_class`: bool = False<br>`output_dir`: str = "."
     - Parse STIX techniques from the given data and write corresponding Java classes.<br>`all_data_sources`: Dictionary to hold all data sources.<br>`all_defenses_bypassed`: Dictionary to hold all defenses bypassed.<br>`all_platforms`: Dictionary to hold all platforms.<br>`stix_data`: MemoryStore or other stix2 DataSource object holding the domain data.<br>`package_name`: The base package name for the output Java classes.<br>`domain`: The domain of ATT&CK stix_data corresponds to, e.g., "enterprise-attack".<br>`verbose_class`: Whether to include verbose class information, by default False.<br>`output_dir`: The root directory for output, by default ".".
