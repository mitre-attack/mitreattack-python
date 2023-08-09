import json
import os

from resources.testing_data import collection, index

from mitreattack.collections.collection_to_index import CollectionToIndex
from mitreattack.collections.index_to_markdown import IndexToMarkdown
from mitreattack.collections.stix_to_collection import STIXToCollection


def test_collection_to_index():
    """Test converting a collection to an index"""
    CollectionToIndex.generate_index(
        name="example3",
        description="exhibit index",
        root_url="www.example.com",
        files=None,
        folders=None,
        sets=[collection],
    )


def test_stix_to_collection():
    """Test converting stix bundle file to a collection"""
    dir = os.path.dirname(__file__)
    ics_bundle_collection = os.path.join(dir, "resources", "ics-bundle.json")
    enterprise_bundle_collection = os.path.join(dir, "resources", "enterprise-bundle.json")
    
    with open(ics_bundle_collection, "r") as fio:
        v20 = json.load(fio)

    with open(enterprise_bundle_collection, "r") as fio:
        v21 = json.load(fio)

    STIXToCollection.stix_to_collection(v20, name="v20_test", version="9.0", description="testing")
    STIXToCollection.stix_to_collection(v21, name="v21_test", version="9.1", description="testing")


def test_index_to_markdown():
    """Test converting index file to a markdown document"""
    IndexToMarkdown.index_to_markdown(index)
