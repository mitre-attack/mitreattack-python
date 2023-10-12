"""Contains CollectionToIndex class, and entrypoint for collectionToIndex_cli."""

import argparse
import json
import os
import re
import uuid

from dateutil.parser import isoparse
from stix2 import Filter, MemoryStore
from tqdm import tqdm


class CollectionToIndex:
    """A CollectionToIndex object."""

    @staticmethod
    def generate_index(name, description, root_url, files=None, folders=None, sets=None):
        """Generate a collection index from the input data and return the index as a dict.

        Arguments
        ---------
            name (string):
                the name of the index
            description (string):
                the description of the index
            root_url (string):
                the root URL where the collections can be found. Specified collection paths will be
                appended to this for the collection URL
            files (string[], optional):
                collection JSON files to include in the index. Cannot be used with folder argument
            folders (string[], optional):
                folders of collection JSON files to include in the index. Cannot be used with
                files argument. Will only match collections that end with a version number
            sets (meta[], optional):
                array of json dictionaries representing stix bundle objects or and array of
                MemoryStore objects to include in the index
        """
        if len([x for x in [files, folders, sets] if x]) > 1:
            print(
                "cannot use multiple arguments (files, folders, sets) at the same time, please use only one "
                "argument at a time"
            )
            return

        if folders:
            version_regex = re.compile(r"(\w+-)+(\d\.?)+.json")
            files = []
            for folder in folders:
                files += list(
                    map(
                        lambda fname: os.path.join(folder, fname),
                        filter(lambda fname: version_regex.match(fname), os.listdir(folder)),
                    )
                )

        cleaned_bundles = []
        if sets:
            if isinstance(sets[0], MemoryStore):
                uset = [
                    dict(
                        type="bundle",
                        id=f"bundle--{x.id}",
                        spec_version="2.0",
                        objects=x.source.query([Filter("type", "=", "x-mitre-collection")]),
                    )
                    for x in sets
                ]
                sets = uset
            for potentially_valid_bundle in sets:
                if potentially_valid_bundle["objects"] is not [[]]:  # Catch case where MemoryStore didn't have a match
                    if any(x["type"] == "x-mitre-collection" for x in potentially_valid_bundle["objects"]):
                        potentially_valid_bundle["objects"] = filter(
                            lambda x: x["type"] == "x-mitre-collection", potentially_valid_bundle["objects"]
                        )
                        cleaned_bundles.append(potentially_valid_bundle)
                    else:
                        print(f"cannot use bundle {potentially_valid_bundle.id} due to lack of collection object")
                else:
                    print(f"cannot use bundle {potentially_valid_bundle.id} due to lack of collection object")

        index_created = None
        index_modified = None
        collections = {}  # STIX ID -> collection object

        if files:
            for collection_bundle_file in tqdm(files, desc="parsing collections"):
                with open(collection_bundle_file, "r", encoding="utf-16") as f:
                    bundle = json.load(f)
                    url = (
                        root_url + collection_bundle_file
                        if root_url.endswith("/")
                        else root_url + "/" + collection_bundle_file
                    )
                    CollectionToIndex._extract_collection(bundle, collections, url)

        if cleaned_bundles:
            for input_bundle in tqdm(cleaned_bundles, desc="transferring input bundles"):
                url = "Imported"
                CollectionToIndex._extract_collection(input_bundle, collections, url)

        for collection in collections.values():
            # set collection name and description from most recently modified version
            collection["name"] = collection["versions"][-1]["name"]
            collection["description"] = collection["versions"][-1]["description"]
            # set index created date according to first created collection
            index_created = (
                index_created
                if index_created and index_created < isoparse(collection["created"])
                else isoparse(collection["created"])
            )
            # delete name and description from all versions
            for version in collection["versions"]:
                # set index created date according to first created collection
                index_modified = (
                    index_modified
                    if index_modified and index_modified > isoparse(version["modified"])
                    else isoparse(version["modified"])
                )
                # delete name and description from version since they aren't used in the output
                del version["name"]
                del version["description"]

        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "description": description,
            "created": index_created.isoformat(),
            "modified": index_modified.isoformat(),
            "collections": list(collections.values()),
        }

    @staticmethod
    def _extract_collection(bundle, collections, url):
        """Extract a collection from a bundle, and build it into the passed in collections dictionary.

        :param bundle: The bundle to work with
        :param collections: A dictionary to place the extracted collection into
        :param url: The corresponding url for this given collection version
        :return: Nothing (Meta - collections dictionary modified)
        """
        for collection_version in filter(lambda x: x["type"] == "x-mitre-collection", bundle["objects"]):
            # parse collection
            if collection_version["id"] not in collections:
                # create
                collections[collection_version["id"]] = {
                    "id": collection_version["id"],
                    "created": collection_version["created"],  # created is the same for all versions
                    "versions": [],
                }
            collection = collections[collection_version["id"]]

            # append this as a version
            collection["versions"].append(
                {
                    "version": collection_version["x_mitre_version"],
                    "url": url,
                    "modified": collection_version["modified"],
                    "name": collection_version["name"],  # this will be deleted later in the code
                    "description": collection_version["description"],  # this will be deleted later in the code
                }
            )
            # ensure the versions are ordered
            collection["versions"].sort(key=lambda version: isoparse(version["modified"]), reverse=True)


def main(args):
    """Entrypoint for collectionToIndex_cli."""
    with open(args.output, "w", encoding="utf-16") as f:
        index = CollectionToIndex.generate_index(
            name=args.name, description=args.description, root_url=args.root_url, files=args.files, folders=args.folders
        )
        print(f"writing {args.output}")
        json.dump(index, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a collection index from a set of collections")
    parser.add_argument(
        "name", type=str, default=None, help="name of the collection index. If omitted a placeholder will be used"
    )
    parser.add_argument(
        "description",
        type=str,
        default=None,
        help="description of the collection index. If omitted a placeholder will be used",
    )
    parser.add_argument(
        "root_url",
        type=str,
        help="the root URL where the collections can be found. Specified collection paths will be appended to this for "
        "the collection URL",
    )
    parser.add_argument(
        "--output", type=str, default="index.json", help="filename for the output collection index file"
    )
    input_options = parser.add_mutually_exclusive_group(required=True)  # require at least one input type
    input_options.add_argument(
        "--files",
        type=str,
        nargs="+",
        default=None,
        metavar=("collection1", "collection2"),
        help="list of collections to include in the index",
    )
    input_options.add_argument(
        "--folders", type=str, nargs="+", default=None, help="folder of JSON files to treat as collections"
    )

    argv = parser.parse_args()
    main(argv)
