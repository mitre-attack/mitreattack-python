from stix2 import CustomObject, ExternalReference
from stix2.properties import StringProperty, ListProperty, TypeProperty, IDProperty, ReferenceProperty, TimestampProperty, BooleanProperty

class CustomStixObject(object):
    def get_version(self) -> str:
        """Get the version of the object

        Returns
        -------
        str
            the object version
        """
        return self.x_mitre_version

def StixObjectFactory(data: dict) -> object:
    """Factory method to convert STIX 2 content into a STIX object

    Parameters
    ----------
    data : dict
        the STIX 2 object content to instantiate, typically
        the result of a stix2 query

    Returns
    -------
    StixObject | stix2.v20.sdo._DomainObject
        an instantiated Python STIX object
    """
    stix_type_to_custom_class = {
        'x-mitre-matrix': Matrix,
        'x-mitre-tactic': Tactic,
        'x-mitre-data-source': DataSource,
        'x-mitre-data-component': DataComponent
    }
 
    if 'type' in data and data['type'] in stix_type_to_custom_class:
        return stix_type_to_custom_class[data['type']](**data, allow_custom=True)
    return data

@CustomObject('x-mitre-matrix', [
    # SDO Common Properties
    ('id', IDProperty('x-mitre-matrix', spec_version='2.0')),
    ('type', TypeProperty('x-mitre-matrix', spec_version='2.0')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('created', TimestampProperty(precision='millisecond')),
    ('modified', TimestampProperty(precision='millisecond')),
    ('revoked', BooleanProperty(default=lambda: False)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    # Matrix Properties
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('tactic_refs', ListProperty(ReferenceProperty(valid_types='x-mitre-tactic', spec_version='2.0'))),
    ('x_mitre_modified_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('x_mitre_version', StringProperty()),
    ('x_mitre_attack_spec_version', StringProperty())
])
class Matrix(CustomStixObject, object):
    pass

@CustomObject('x-mitre-tactic', [
    # SDO Common Properties
    ('id', IDProperty('x-mitre-tactic', spec_version='2.0')),
    ('type', TypeProperty('x-mitre-tactic', spec_version='2.0')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('created', TimestampProperty(precision='millisecond')),
    ('modified', TimestampProperty(precision='millisecond')),
    ('revoked', BooleanProperty(default=lambda: False)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    # Tactic Properties
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('x_mitre_domains', ListProperty(StringProperty())),
    ('x_mitre_shortname', StringProperty()),
    ('x_mitre_modified_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('x_mitre_version', StringProperty()),
    ('x_mitre_attack_spec_version', StringProperty())
])
class Tactic(CustomStixObject, object):
    def get_shortname(self) -> str:
        """Get the tactic shortname

        Returns
        -------
        str
            the shortname of the tactic
        """
        return self.x_mitre_shortname

@CustomObject('x-mitre-data-source', [
    # SDO Common Properties
    ('id', IDProperty('x-mitre-data-source', spec_version='2.0')),
    ('type', TypeProperty('x-mitre-data-source', spec_version='2.0')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('created', TimestampProperty(precision='millisecond')),
    ('modified', TimestampProperty(precision='millisecond')),
    ('revoked', BooleanProperty(default=lambda: False)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    # Data Source Properties
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('x_mitre_platforms', ListProperty(StringProperty())),
    ('x_mitre_domains', ListProperty(StringProperty())),
    ('x_mitre_collection_layers', ListProperty(StringProperty())),
    ('x_mitre_contributors', ListProperty(StringProperty())),
    ('x_mitre_modified_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('x_mitre_version', StringProperty()),
    ('x_mitre_attack_spec_version', StringProperty())
])
class DataSource(CustomStixObject, object):
    pass

@CustomObject('x-mitre-data-component', [
    # SDO Common Properties
    ('id', IDProperty('x-mitre-data-component', spec_version='2.0')),
    ('type', TypeProperty('x-mitre-data-component', spec_version='2.0')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('created', TimestampProperty(precision='millisecond')),
    ('modified', TimestampProperty(precision='millisecond')),
    ('revoked', BooleanProperty(default=lambda: False)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    # Data Component Properties
    ('name', StringProperty()),
    ('description', StringProperty()),
    ('x_mitre_data_source_ref', ReferenceProperty(valid_types='x-mitre-data-source', spec_version='2.0')),
    ('x_mitre_modified_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.0')),
    ('x_mitre_version', StringProperty()),
    ('x_mitre_attack_spec_version', StringProperty())
])
class DataComponent(CustomStixObject, object):
    pass
