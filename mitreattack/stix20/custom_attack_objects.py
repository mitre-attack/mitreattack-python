"""The classes found here are how ATT&CK objects can be represented as custom STIX objects instead of python dictionaries."""

from typing import Any, Union

import stix2
import stix2.v20
from stix2 import CustomObject, ExternalReference
from stix2.properties import (
    BooleanProperty,
    DictionaryProperty,
    IDProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
)


class CustomStixObject(object):
    """Custom STIX object used for ATT&CK objects.

    Note: This class supports dynamic attributes as defined by the STIX 2.0 specification.
    """

    # id: str
    # name: str

    def __getattr__(self, name: str):
        # Try dynamic attribute (for STIX2 custom objects)
        if name in self.__dict__:
            return self.__dict__[name]
        # Try dict-like access (if this object is dict-like)
        if hasattr(self, "get") and callable(getattr(self, "get")):
            value = self.get(name, None)
            if value is not None:
                return value
        # Fallback: raise AttributeError as usual
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    def get_version(self) -> str:
        """Get the version of the object.

        Returns
        -------
        str
            the object version
        """
        version = getattr(self, "x_mitre_version", None)
        if version is None:
            raise AttributeError("x_mitre_version attribute is missing")
        return version

    def serialize(self, pretty: bool = True) -> str:
        """Serialize the object to a JSON string."""
        raise NotImplementedError("serialize() should be provided by the STIX2 base class.")


def StixObjectFactory(data: dict) -> Union[CustomStixObject, stix2.v20.sdo._DomainObject, dict[str, Any]]:
    """Convert STIX 2 content into a STIX object (factory method).

    Parameters
    ----------
    data : dict
        the STIX 2 object content to instantiate, typically
        the result of a stix2 query

    Returns
    -------
    CustomStixObject | dict
        If the input data is a recognized custom ATT&CK object type,
        returns an instance of the corresponding CustomStixObject subclass
        (e.g., Matrix, Tactic, DataSource, DataComponent, Asset).
        Otherwise, returns the original dictionary.
    """
    stix_type_to_custom_class = {
        "x-mitre-matrix": Matrix,
        "x-mitre-tactic": Tactic,
        "x-mitre-data-source": DataSource,
        "x-mitre-data-component": DataComponent,
        "x-mitre-asset": Asset,
    }

    stix_type = data.get("type")

    if data and stix_type in stix_type_to_custom_class:
        return stix_type_to_custom_class[stix_type](**data, allow_custom=True)
    return stix2.parse(data=data, allow_custom=True)


@CustomObject(
    "x-mitre-matrix",
    [
        # SDO Common Properties
        ("id", IDProperty("x-mitre-matrix", spec_version="2.0")),
        ("type", TypeProperty("x-mitre-matrix", spec_version="2.0")),
        ("created_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("created", TimestampProperty(precision="millisecond")),
        ("modified", TimestampProperty(precision="millisecond")),
        ("revoked", BooleanProperty(default=lambda: False)),
        ("external_references", ListProperty(ExternalReference)),
        ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.0"))),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("x_mitre_modified_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        # Matrix Properties
        ("tactic_refs", ListProperty(ReferenceProperty(valid_types="x-mitre-tactic", spec_version="2.0"))),
    ],
)
class Matrix(CustomStixObject, object):
    """Custom Matrix object of type stix2.CustomObject.

    Custom Properties
    -----------------
    tactic_refs: list[str]
    """

    pass


@CustomObject(
    "x-mitre-tactic",
    [
        # SDO Common Properties
        ("id", IDProperty("x-mitre-tactic", spec_version="2.0")),
        ("type", TypeProperty("x-mitre-tactic", spec_version="2.0")),
        ("created_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("created", TimestampProperty(precision="millisecond")),
        ("modified", TimestampProperty(precision="millisecond")),
        ("revoked", BooleanProperty(default=lambda: False)),
        ("external_references", ListProperty(ExternalReference)),
        ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.0"))),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("x_mitre_domains", ListProperty(StringProperty())),
        ("x_mitre_modified_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        # Tactic Properties
        ("x_mitre_shortname", StringProperty()),
    ],
)
class Tactic(CustomStixObject, object):
    """Custom Tactic object of type stix2.CustomObject.

    Custom Properties
    -----------------
    x_mitre_shortname: str
    """

    def get_shortname(self) -> str:
        """Get the tactic shortname.

        Returns
        -------
        str
            the shortname of the tactic
        """
        shortname = getattr(self, "x_mitre_shortname", None)
        if shortname is None:
            raise AttributeError("x_mitre_shortname attribute is missing")
        return shortname


@CustomObject(
    "x-mitre-data-source",
    [
        # SDO Common Properties
        ("id", IDProperty("x-mitre-data-source", spec_version="2.0")),
        ("type", TypeProperty("x-mitre-data-source", spec_version="2.0")),
        ("created_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("created", TimestampProperty(precision="millisecond")),
        ("modified", TimestampProperty(precision="millisecond")),
        ("revoked", BooleanProperty(default=lambda: False)),
        ("external_references", ListProperty(ExternalReference)),
        ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.0"))),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("x_mitre_domains", ListProperty(StringProperty())),
        ("x_mitre_contributors", ListProperty(StringProperty())),
        ("x_mitre_modified_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        # Data Source Properties
        ("x_mitre_platforms", ListProperty(StringProperty())),
        ("x_mitre_collection_layers", ListProperty(StringProperty())),
    ],
)
class DataSource(CustomStixObject, object):
    """Custom DataSource object of type stix2.CustomObject.

    Custom Properties
    -----------------
    x_mitre_platforms: list[str]
    x_mitre_collection_layers: list[str]
    """

    pass


@CustomObject(
    "x-mitre-data-component",
    [
        # SDO Common Properties
        ("id", IDProperty("x-mitre-data-component", spec_version="2.0")),
        ("type", TypeProperty("x-mitre-data-component", spec_version="2.0")),
        ("created_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("created", TimestampProperty(precision="millisecond")),
        ("modified", TimestampProperty(precision="millisecond")),
        ("revoked", BooleanProperty(default=lambda: False)),
        ("external_references", ListProperty(ExternalReference)),
        ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.0"))),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("x_mitre_modified_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        # Data Component Properties
        ("x_mitre_data_source_ref", ReferenceProperty(valid_types="x-mitre-data-source", spec_version="2.0")),
    ],
)
class DataComponent(CustomStixObject, object):
    """Custom DataComponent object of type stix2.CustomObject.

    Custom Properties
    -----------------
    x_mitre_data_source_ref: str
    """

    pass


@CustomObject(
    "x-mitre-asset",
    [
        # SDO Common Properties
        ("id", IDProperty("x-mitre-asset", spec_version="2.0")),
        ("type", TypeProperty("x-mitre-asset", spec_version="2.0")),
        ("created_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("created", TimestampProperty(precision="millisecond")),
        ("modified", TimestampProperty(precision="millisecond")),
        ("revoked", BooleanProperty(default=lambda: False)),
        ("external_references", ListProperty(ExternalReference)),
        ("object_marking_refs", ListProperty(ReferenceProperty(valid_types="marking-definition", spec_version="2.0"))),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        ("x_mitre_modified_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.0")),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        ("x_mitre_domains", ListProperty(StringProperty())),
        ("x_mitre_contributors", ListProperty(StringProperty())),
        # Asset Properties
        ("sectors", ListProperty(StringProperty())),
        ("x_mitre_related_assets", ListProperty(DictionaryProperty())),
        ("x_mitre_platforms", ListProperty(StringProperty())),
    ],
)
class Asset(CustomStixObject, object):
    """Custom Asset object of type stix2.CustomObject.

    Custom Properties
    -----------------
    x_mitre_platforms: list[str]
    x_mitre_related_assets: list[object]
    """

    pass
