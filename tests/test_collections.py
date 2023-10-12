import json
from pathlib import Path

from argparse import Namespace
from resources.testing_data import collection, index

from mitreattack.collections.collection_to_index import CollectionToIndex, main as CTI_main
from mitreattack.collections.index_to_markdown import IndexToMarkdown, main as ITM_main
from mitreattack.collections.stix_to_collection import STIXToCollection, main as STC_main


class TestCollectionToIndex:
    def test_invalid_arguments(self, capsys):
        """Test converting a collection to an index with invalid arguments provided"""
        index = CollectionToIndex.generate_index(
            name="name",
            description="description",
            root_url="www.example.com",
            files=["/path/to/collection1.json"],
            sets=[collection],
        )
        captured = capsys.readouterr()

        assert index is None
        assert captured.out.strip() == (
            "cannot use multiple arguments (files, folders, sets) "
            "at the same time, please use only one argument at a time"
        )

    def test_files(self):
        """Test converting a collection to an index with files provided"""
        name = "Files Example"
        description = "Files index"
        index = CollectionToIndex.generate_index(
            name=name,
            description=description,
            root_url="www.example.com",
            files=[str(Path(__file__).parent / "resources" / "collection-1.json")],
        )

        assert index["name"] == name
        assert index["description"] == description

    def test_folders(self):
        """Test converting a collection to an index with folders provided"""
        name = "Folders Example"
        description = "Folders index"
        index = CollectionToIndex.generate_index(
            name=name,
            description=description,
            root_url="www.example.com",
            folders=[str(Path(__file__).parent / "resources")],
        )

        assert index["name"] == name
        assert index["description"] == description

    def test_sets(self):
        """Test converting a collection to an index with sets provided"""
        name = "Sets Example"
        description = "Sets index"
        index = CollectionToIndex.generate_index(
            name=name,
            description=description,
            root_url="www.example.com",
            sets=[collection],
        )

        assert index["name"] == name
        assert index["description"] == description

    def test_main(self, tmp_path: Path):
        """Test converting a collection to an index main method"""
        ics_bundle_collection = Path(__file__).parent / "resources" / "collection-1.json"
        output_path = tmp_path / "output.idx"

        CTI_main(
            Namespace(
                **{
                    "name": "Collection name",
                    "description": "Collection description",
                    "root_url": "https://example.com/",
                    "output": str(output_path),
                    "files": [str(ics_bundle_collection)],
                    "folders": None,
                    "sets": None,
                }
            )
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0


class TestStixToCollection:
    test_dir = Path(__file__).parent

    def test_name_version_description(self):
        """Test converting stix to a collection name and version fields"""
        ics_bundle_collection = self.test_dir / "resources" / "ics-bundle.json"
        enterprise_bundle_collection = self.test_dir / "resources" / "enterprise-bundle.json"

        name = "v20_test"
        version = "9.0"
        description = "testing"
        with open(str(ics_bundle_collection), "r") as fio:
            v20 = json.load(fio)
        v20_collection = STIXToCollection.stix_to_collection(
            v20,
            name=name,
            version=version,
            description=description,
        )

        assert v20_collection["objects"][0]["name"] == name
        assert v20_collection["objects"][0]["description"] == description
        assert v20_collection["objects"][0]["x_mitre_version"] == version

        name = "v21_test"
        version = "9.1"
        description = "testing"
        with open(str(enterprise_bundle_collection), "r", encoding="utf-16") as fio:
            v21 = json.load(fio)
        v21_collection = STIXToCollection.stix_to_collection(
            v21,
            name=name,
            version=version,
            description=description,
        )

        assert v21_collection["objects"][0]["name"] == name
        assert v21_collection["objects"][0]["description"] == description
        assert v21_collection["objects"][0]["x_mitre_version"] == version

        v21_collection = STIXToCollection.stix_to_collection(
            v21,
            name=name,
            version=version,
            description=None,
        )
        assert v21_collection["objects"][0]["description"] == (
            "This collection was autogenerated by STIXToCollection, as part of mitreattack-python"
        )

    def test_bundle(self):
        """Test converting stix bundle to a collection"""
        collection_path = self.test_dir / "resources" / "collection-1.json"
        with open(str(collection_path), "r", encoding="utf-16") as fio:
            stix_data = json.load(fio)
        collection = STIXToCollection.stix_to_collection(
            stix_data,
            name="Test bundle",
            version="9.0",
            description="A test",
        )

        assert collection == stix_data

    def test_version_validity(self, capsys):
        """Test converting stix to a collection version validity"""
        stix_data = {
            "type": "bundle",
            "id": "bundle--02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
            "spec_version": "1.9",
            "objects": [],
        }
        collection = STIXToCollection.stix_to_collection(
            stix_data,
            name="Version test",
            version="9.0",
            description="A test",
        )
        captured = capsys.readouterr()

        assert collection is None
        assert captured.out.strip() == (
            "[ERROR] - version 1.9 is not one of [2.0, 2.1]. "
            "This module only processes stix 2.0 and stix 2.1 bundles."
        )

    def test_malformed_object(self, capsys):
        stix_data = {
            "type": "bundle",
            "id": "bundle--02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
            "spec_version": "2.1",
            "objects": [{"type": "not-x-mitre-collection"}],
        }
        collection = STIXToCollection.stix_to_collection(
            stix_data,
            name="Malformed object test",
            version="9.0",
            description="testing",
        )
        captured = capsys.readouterr()

        assert collection is None
        assert captured.out.strip() == (
            "[ERROR] - object {'type': 'not-x-mitre-collection'} "
            "is missing a necessary field: 'id'. Exiting this script..."
        )

    def test_object_marking_refs(self):
        """Test converting stix to a collection with object marking refs field present"""
        stix_data = {
            "type": "bundle",
            "id": "bundle--02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "not-x-mitre-collection",
                    "id": "test",
                    "modified": "date.now()",
                    "object_marking_refs": ["test"],
                }
            ],
        }
        collection = STIXToCollection.stix_to_collection(
            stix_data,
            name="Object marking refs test",
            version="9.0",
            description="A test",
        )

        assert collection["objects"][0]["object_marking_refs"] == ["test"]

    def test_created_by_ref(self, capsys):
        """Test converting stix to a collection with created by ref field present"""
        stix_data = {
            "type": "bundle",
            "id": "bundle--02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "not-x-mitre-collection",
                    "id": "test1",
                    "modified": "date.now()",
                    "created_by_ref": "ref1",
                },
                {
                    "type": "not-x-mitre-collection",
                    "id": "test2",
                    "modified": "date.now()",
                    "created_by_ref": "ref2",
                },
            ],
        }
        collection = STIXToCollection.stix_to_collection(
            stix_data,
            name="Created by ref test",
            version="9.0",
            description="A test",
        )
        captured = capsys.readouterr()

        assert collection["objects"][0]["created_by_ref"] == "ref1"
        assert captured.out.strip() == (
            "[NOTE] multiple 'created_by_ref' values detected. "
            "ref1 (first encountered) will take precedence over ref2"
        )

    def test_main(self, tmp_path: Path):
        """Test converting stix to a collection main method"""
        input_path = self.test_dir / "resources" / "collection-1.json"
        output_path = tmp_path / "output.json"

        STC_main(
            Namespace(
                **{
                    "name": "Collection name",
                    "description": "Collection description",
                    "version": "9.1",
                    "input": str(input_path),
                    "output": str(output_path),
                }
            )
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0


class TestIndexToMarkdown:
    def test_headers(self):
        """Test converting index file to a markdown headers"""
        markdown = IndexToMarkdown.index_to_markdown(index)

        assert "### MITRE ATT&CK Collections" in markdown
        assert "#### Enterprise ATT&CK" in markdown
        assert "#### Mobile ATT&CK" in markdown
        assert "#### ICS ATT&CK" in markdown

    def test_main(self, tmp_path: Path):
        """Test converting index file to a markdown main method"""
        index_path = Path(__file__).parent / "resources" / "index.json"
        output_path = tmp_path / "output.idx"
        ITM_main(
            Namespace(
                **{
                    "index": str(index_path),
                    "output": str(output_path),
                }
            )
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0
