"""Tests for network operations and CTI data loading."""

import pytest
import requests
import responses

from mitreattack.diffStix.core.diff_stix import DiffStix


class TestNetwork:
    """Tests for network operations and CTI data loading."""

    @responses.activate
    def test_cti_connection_timeout(self):
        """Test handling of connection timeout errors."""
        # Mock the URL with a timeout exception
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        responses.add(
            responses.GET,
            url,
            body=requests.exceptions.Timeout("Connection timed out"),
        )
        diffstix = DiffStix.__new__(DiffStix)
        diffstix.domains = ["enterprise-attack"]
        diffstix.data = {"old": {"enterprise-attack": {}}, "new": {"enterprise-attack": {}}}

        # Expect SystemExit if the method calls sys.exit() on failure
        with pytest.raises(requests.exceptions.Timeout):
            diffstix.get_datastore_from_mitre_cti(domain="enterprise-attack", datastore_version="old")

    @responses.activate
    def test_get_datastore_from_mitre_cti_http_error(self):
        """Test handling of HTTP errors during CTI data loading."""
        responses.add(
            responses.GET,
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            status=404,
        )
        diffstix = DiffStix.__new__(DiffStix)
        diffstix.domains = ["enterprise-attack"]
        diffstix.data = {"old": {"enterprise-attack": {}}, "new": {"enterprise-attack": {}}}
        with pytest.raises(SystemExit):
            diffstix.get_datastore_from_mitre_cti(domain="enterprise-attack", datastore_version="old")

    @responses.activate
    def test_get_datastore_from_mitre_cti_success(self, sample_technique_object):
        """Test successful data loading from CTI repository."""
        mock_stix_data = {"objects": [sample_technique_object]}
        responses.add(
            responses.GET,
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            json=mock_stix_data,
            status=200,
        )
        diffstix = DiffStix.__new__(DiffStix)
        diffstix.domains = ["enterprise-attack"]
        diffstix.data = {"old": {"enterprise-attack": {}}, "new": {"enterprise-attack": {}}}
        datastore = diffstix.get_datastore_from_mitre_cti(domain="enterprise-attack", datastore_version="old")
        assert datastore is not None
        objects = datastore.query([])
        assert len(objects) == 1
        assert objects[0]["name"] == sample_technique_object["name"]
