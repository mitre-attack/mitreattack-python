"""
Tests for custom STIX 2.0 attack objects in the mitreattack.stix20 module.

This module verifies the correct behavior and properties of custom ATT&CK objects
including DataComponent, DataSource, Matrix, Tactic, Asset, Analytic,
DetectionStrategy, and the StixObjectFactory.
"""

import pytest
import stix2
import stix2.exceptions

from mitreattack.stix20.custom_attack_objects import (
    Analytic,
    Asset,
    DataComponent,
    DataSource,
    DetectionStrategy,
    Matrix,
    StixObjectFactory,
    Tactic,
)


class TestCustomAttackObjects:
    """
    Test suite for custom ATT&CK STIX 2.0 objects and their factory.

    This class contains tests for the creation and properties of custom ATT&CK objects
    including DataComponent, DataSource, Matrix, Tactic, Asset, Analytic,
    DetectionStrategy, and the StixObjectFactory.
    """

    def test_data_component(self):
        """Test DataComponent creation and properties."""
        name = "Data component"
        data_component = DataComponent(name=name)

        assert data_component.name == name
        assert data_component.type == "x-mitre-data-component"

    def test_data_source(self):
        """Test DataSource creation and properties."""
        name = "Data source"
        data_source = DataSource(name=name)

        assert data_source.name == name
        assert data_source.type == "x-mitre-data-source"

    def test_matrix(self):
        """Test Matrix creation and properties."""
        name = "Matrix"
        matrix = Matrix(name=name)

        assert matrix.name == name
        assert matrix.type == "x-mitre-matrix"

    def test_stix_object_factory(self):
        """Test StixObjectFactory instantiation and error handling."""
        type_id_class_mapping = {
            "x-mitre-data-component": DataComponent,
            "x-mitre-data-source": DataSource,
            "x-mitre-matrix": Matrix,
            "x-mitre-tactic": Tactic,
            "x-mitre-asset": Asset,
            "x-mitre-analytic": Analytic,
            "x-mitre-detection-strategy": DetectionStrategy,
        }

        object_name = "Object name"
        for type_id, cls in type_id_class_mapping.items():
            instance = StixObjectFactory({"type": type_id, "name": object_name})

            assert isinstance(instance, cls)
            assert instance.name == object_name
            assert instance.type == type_id

        with pytest.raises(stix2.exceptions.ParseError) as exc:
            data = {"something": "else"}
            StixObjectFactory(data)

        assert "Can't parse object with no 'type' property" in str(exc.value)
        assert exc.type is stix2.exceptions.ParseError

    def test_tactic(self):
        """Test Tactic creation and properties."""
        name = "Tactic"
        shortname = "Tactic shortname"
        version = "Tactic version"
        tactic = Tactic(**{"name": name, "x_mitre_shortname": shortname, "x_mitre_version": version})

        assert tactic.name == name
        assert tactic.type == "x-mitre-tactic"
        assert tactic.get_shortname() == shortname
        assert tactic.get_version() == version

    def test_asset(self):
        """Test Asset creation and properties."""
        name = "Asset"
        asset = Asset(name=name)

        assert asset.name == name
        assert asset.type == "x-mitre-asset"

    def test_analytic(self):
        """Test Analytic creation and properties."""
        name = "Analytic"
        analytic = Analytic(name=name)

        assert analytic.name == name
        assert analytic.type == "x-mitre-analytic"

    def test_detection_strategy(self):
        """Test Detection Strategy creation and properties."""
        name = "Detection Strategy"
        detection_strategy = DetectionStrategy(name=name)

        assert detection_strategy.name == name
        assert detection_strategy.type == "x-mitre-detection-strategy"
