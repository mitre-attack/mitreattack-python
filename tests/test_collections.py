from mitreattack.collections.collection_to_index import CollectionToIndex
from mitreattack.collections.stix_to_collection import STIXToCollection
from mitreattack.collections.index_to_markdown import IndexToMarkdown
from tests.resources.testing_data import collection, index
import json

class TestCollections:
    @staticmethod
    def test_collection_to_index():
        output_index = CollectionToIndex.generate_index(name='example3', description='exhibit index',
                                                        root_url='www.example.com',
                                                        files=None, folders=None, sets=[collection])
    @staticmethod
    def test_stix_to_collection():
        with open('resources/enterprise-bundle.json', 'r') as fio:
            v21 = json.load(fio)
        with open('resources/ics-bundle.json', 'r') as fio:
            v20 = json.load(fio)
        out21 = STIXToCollection.stix_to_collection(v21, name='v21_test', version="9.1", description='testing')
        out20 = STIXToCollection.stix_to_collection(v20, name='v20_test', version='9.0', description='testing')

    @staticmethod
    def test_index_to_markdown():
        outMD = IndexToMarkdown.index_to_markdown(index)
