Accessing ATT&CK data in python
===============

**Accessing ATT&CK data in python**

There are several ways to acquire the ATT&CK data in Python. All of them will provide an object
implementing the DataStore API and can be used interchangeably with the recipes provided in the [Python recipes](#Python-Recipes) section.

This section utilizes the [stix2 python library](https://github.com/oasis-open/cti-python-stix2). Please refer to the [STIX2 Python API Documentation](https://stix2.readthedocs.io/en/latest/) for more information on how to work with STIX programmatically.

**Requirements and imports**

Before installing requirements, we recommend setting up a virtual environment:

1. Create virtual environment:
    - macOS and Linux: `python3 -m venv env`
    - Windows: `py -m venv env`
2. Activate the virtual environment:
    - macOS and Linux: `source env/bin/activate`
    - Windows: `env/Scripts/activate.bat`

**stix2**

[stix2 can be installed by following the instructions on their repository](https://github.com/oasis-open/cti-python-stix2#installation). Imports for the recipes in this repository can be done from the base package, for example:

.. code-block:: python

    from stix2 import Filter


However, if you are aiming to extend the ATT&CK dataset with new objects or implement complex workflows, you may need to use the `v20` specifier for some imports. This ensures that the objects use the STIX 2.0 API instead of the STIX 2.1 API. For example:

.. code-block:: python

    from stix2.v20 import AttackPattern


You can see a full list of the classes which have versioned imports [here](https://stix2.readthedocs.io/en/latest/api/stix2.v20.html).

**taxii2client**

[taxii2-client can be installed by following the instructions on their repository](https://github.com/oasis-open/cti-taxii-client#installation). The ATT&CK TAXII server implements the 2.0 version of the TAXII specification, but the default import of `taxii2client` (version 2.0.0 and above) uses the 2.1 version of the TAXII specification, which can lead to 406 responses when connecting to our TAXII server if not accounted for.

If the TAXII Client is getting a 406 Response, make sure you are running the latest version (`pip install --upgrade stix2` or `pip install --upgrade taxii2-client`). In addition, make sure you are running the 2.0 version of the client (using the `v20` import) as shown below in order to communicate with the ATT&CK TAXII 2.0 Server.

.. code-block:: python

    from taxii2client.v20 import Collection


**Access local content**

Many users may opt to access the ATT&CK content via a local copy of the STIX data on this repo. This can be advantageous for several reasons:

- Doesn't require internet access after the initial download
- User can modify the ATT&CK content if desired
- Downloaded copy is static, so updates to the ATT&CK catalog won't cause bugs in automated workflows. User can still manually update by cloning a fresh version of the data

**Access via FileSystemSource**

Each domain in this repo is formatted according to the [STIX2 FileSystem spec](https://stix2.readthedocs.io/en/latest/guide/filesystem.html).
Therefore you can use a `FileSystemSource` to load a domain, for example to load the enterprise-attack domain:

.. code-block:: python

    from stix2 import FileSystemSource

src = FileSystemSource('./cti/enterprise-attack')


**Access via bundle**

If you instead prefer to download just the domain bundle, e.g [enterprise-attack.json](/enterprise-attack/enterprise-attack.json), you can still load this using a MemoryStore:

.. code-block:: python

    from stix2 import MemoryStore

    src = MemoryStore()
    src.load_from_file("enterprise-attack.json")


**Access live content**

Some users may instead prefer to access "live" ATT&CK content over the internet. This is advantageous for several reasons:

- Always stays up to date with the evolving ATT&CK catalog
- Doesn't require an initial download of the ATT&CK content, generally requires less setup

**Access from the ATT&CK TAXII server**

Users can access the ATT&CK data from the official ATT&CK TAXII server. In TAXII, the ATT&CK domains are represented as collections with static IDs:

.. list-table::  
   :widths: 50 50
   :header-rows: 1

   * - domain
     - collection ID
   * - `enterprise-attack`
     - `95ecc380-afe9-11e4-9b6c-751b66dd541e`
   * - `mobile-attack` 
     - `2f669986-b40b-4423-b720-4396ca6a462b`
   * - `ics-attack`
     - `02c3ef24-9cd4-48f3-a99f-b74ce24f1d34`

You can also get a list of available collection from the server directly:

.. code-block:: python

    from taxii2client.v20 import Server # only specify v20 if your installed version is >= 2.0.0

    server = Server("https://cti-taxii.mitre.org/taxii/")
    api_root = server.api_roots[0]
    # Print name and ID of all ATT&CK domains available as collections
    for collection in api_root.collections:
        print(collection.title.ljust(20) + collection.id)


The following recipe demonstrates how to access the enterprise-attack data from the TAXII server.

.. code-block:: python

    from stix2 import TAXIICollectionSource
    from taxii2client.v20 import Collection # only specify v20 if your installed version is >= 2.0.0

    collections = {
        "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
        "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
        "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
    }

    collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
    src = TAXIICollectionSource(collection)


For more about TAXII, please see oasis-open's [Introduction to TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro).

**Access from Github via requests**

Users can alternatively access the data from MITRE/CTI using HTTP requests, and load the resulting content into a MemoryStore.
While typically the TAXII method is more desirable for "live" access, this method can be useful if you want to
access data on a branch of the MITRE/CTI repo (the TAXII server only holds the master branch) or in the case of a TAXII server outage.

.. code-block:: python

    import requests
    from stix2 import MemoryStore

    def get_data_from_branch(domain, branch="master"):
        """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
        stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
        return MemoryStore(stix_data=stix_json["objects"])

    src = get_data_from_branch("enterprise-attack")


**Access a specific version of ATT&CK**

ATT&CK versions are tracked on the MITRE/CTI repo using [tags](https://github.com/mitre/cti/tags). Tags prefixed with `ATT&CK-v` correspond to ATT&CK versions and tags prefixed with `CAPEC-v` correspond to CAPEC versions. You can find more information about ATT&CK versions on the [versions of ATT&CK page](https://attack.mitre.org/resources/versions/) on the ATT&CK website.

In addition to checking out the repo under the tag for a given version or downloading the STIX from github using your browser, you can also use a variation on the [requests method](#access-from-github-via-requests) to access a particular version of ATT&CK:

.. code-block:: python

    import requests
    from stix2 import MemoryStore

    def get_data_from_version(domain, version):
        """get the ATT&CK STIX data for the given version from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'."""
        stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
        return MemoryStore(stix_data=stix_json["objects"])

    src = get_data_from_version("enterprise-attack", "5.2")


You can get a list of ATT&CK versions programmatically using the github API:

.. code-block:: python

    import requests
    import re

    refToTag = re.compile(r"ATT&CK-v(.*)")
    tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
    versions = list(map(lambda tag: refToTag.search(tag["ref"]).groups()[0] , filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))
    # versions = ["1.0", "2.0", ...]


**Access multiple domains simultaneously**

Because ATT&CK is stored in multiple domains (as of this writing, enterprise-attack, mobile-attack and ics-attack), the above methodologies will only allow you to work
with a single domain at a time. While oftentimes the hard separation of domains is advantageous, occasionally it is useful to combine
domains into a single DataStore. Use any of the methods above to acquire the individual datastores, and then use the following approach to combine them into
a single CompositeDataSource:

.. code-block:: python
    
    from stix2 import CompositeDataSource

    src = CompositeDataSource()
    src.add_data_sources([enterprise_attack_src, mobile_attack_src, ics_attack_src])


You can then use this CompositeDataSource just as you would the DataSource for an individual domain.



    
