"""Tests for layer output generation and validation."""

import json
from pathlib import Path

from mitreattack.diffStix.formatters.layer_output import layers_dict_to_files


class TestLayerOutput:
    """Tests for layer output generation and validation."""

    def test_layers_dict_to_files_all_domains(self, tmp_path, mock_layers_dict):
        """Test writing layer files for all domains."""
        outfiles = [str(tmp_path / "enterprise.json"), str(tmp_path / "mobile.json"), str(tmp_path / "ics.json")]
        layers_dict_to_files(outfiles, mock_layers_dict)
        for outfile in outfiles:
            assert Path(outfile).exists()
        with open(outfiles[0]) as f:
            enterprise_data = json.load(f)
        assert enterprise_data["name"] == "Test Enterprise Updates"
        assert enterprise_data["domain"] == "enterprise-attack"
        with open(outfiles[1]) as f:
            mobile_data = json.load(f)
        assert mobile_data["name"] == "Test Mobile Updates"
        with open(outfiles[2]) as f:
            ics_data = json.load(f)
        assert ics_data["name"] == "Test ICS Updates"
