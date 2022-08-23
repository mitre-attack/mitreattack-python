import json

from mitreattack.collections.collection_to_index import CollectionToIndex
from mitreattack.collections.index_to_markdown import IndexToMarkdown
from mitreattack.collections.stix_to_collection import STIXToCollection
from tests.resources.testing_data import collection, index


class TestCollections:
    @staticmethod
    def test_collection_to_index():
        """Test converting a collection to an index"""
        output_index = CollectionToIndex.generate_index(
            name="example3",
            description="exhibit index",
            root_url="www.example.com",
            files=None,
            folders=None,
            sets=[collection],
        )

    @staticmethod
    def test_stix_to_collection():
        """Test converting stix bundle file to a collection"""
        with open("resources/enterprise-bundle.json", "r") as fio:
            v21 = json.load(fio)
        with open("resources/ics-bundle.json", "r") as fio:
            v20 = json.load(fio)
        out21 = STIXToCollection.stix_to_collection(v21, name="v21_test", version="9.1", description="testing")
        out20 = STIXToCollection.stix_to_collection(v20, name="v20_test", version="9.0", description="testing")

    @staticmethod
    def test_index_to_markdown():
        """Test converting index file to a markdown document"""
        outMD = IndexToMarkdown.index_to_markdown(index)
