import json
from argparse import Namespace
from pathlib import Path

from mitreattack.collections.collection_to_index import CollectionToIndex
from mitreattack.collections.collection_to_index import main as CTI_main
from mitreattack.collections.index_to_markdown import IndexToMarkdown
from mitreattack.collections.index_to_markdown import main as ITM_main

from .resources.testing_data import collection, index


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
