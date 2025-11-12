"""URL generation utilities for ATT&CK objects."""

from typing import Optional


def get_relative_url_from_stix(stix_object: dict) -> Optional[str]:
    """Parse the website url from a stix object.

    Parameters
    ----------
    stix_object : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    Optional[str]
        The relative URL for the ATT&CK object.
    """
    is_subtechnique = stix_object["type"] == "attack-pattern" and stix_object.get("x_mitre_is_subtechnique")

    if stix_object.get("external_references"):
        url = stix_object["external_references"][0]["url"]
        split_url = url.split("/")
        splitfrom = -3 if is_subtechnique else -2
        link = "/".join(split_url[splitfrom:])
        return link
    return None


def get_relative_data_component_url(datasource: dict, datacomponent: dict) -> str:
    """Create url of data component with parent data source.

    Parameters
    ----------
    datasource : dict
        The data source STIX object.
    datacomponent : dict
        The data component STIX object.

    Returns
    -------
    str
        The relative URL for the data component.
    """
    return f"{get_relative_url_from_stix(stix_object=datasource)}/#{'%20'.join(datacomponent['name'].split(' '))}"
