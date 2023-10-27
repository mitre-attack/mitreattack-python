from mitreattack.stix20.custom_attack_objects import DataComponent, DataSource, Matrix, StixObjectFactory, Tactic, Asset


class TestCustomAttackObjects:
    def test_data_component(self):
        name = "Data component"
        data_component = DataComponent(name=name)

        assert data_component.name == name
        assert data_component.type == "x-mitre-data-component"

    def test_data_source(self):
        name = "Data source"
        data_source = DataSource(name=name)

        assert data_source.name == name
        assert data_source.type == "x-mitre-data-source"

    def test_matrix(self):
        name = "Matrix"
        matrix = Matrix(name=name)

        assert matrix.name == name
        assert matrix.type == "x-mitre-matrix"

    def test_stix_object_factory(self):
        type_id_class_mapping = {
            "x-mitre-data-component": DataComponent,
            "x-mitre-data-source": DataSource,
            "x-mitre-matrix": Matrix,
            "x-mitre-tactic": Tactic,
            "x-mitre-asset": Asset,
        }

        object_name = "Object name"
        for type_id, cls in type_id_class_mapping.items():
            instance = StixObjectFactory({"type": type_id, "name": object_name})

            assert isinstance(instance, cls)
            assert instance.name == object_name
            assert instance.type == type_id

        data = {"something": "else"}
        assert StixObjectFactory(data) == data

    def test_tactic(self):
        name = "Tactic"
        shortname = "Tactic shortname"
        version = "Tactic version"
        tactic = Tactic(**{"name": name, "x_mitre_shortname": shortname, "x_mitre_version": version})

        assert tactic.name == name
        assert tactic.type == "x-mitre-tactic"
        assert tactic.get_shortname() == shortname
        assert tactic.get_version() == version

    def test_asset(self):
        name = "Asset"
        asset = Asset(name=name)

        assert asset.name == name
        assert asset.type == "x-mitre-asset"
