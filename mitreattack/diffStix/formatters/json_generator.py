"""JSON changelog output generator."""

from loguru import logger

from mitreattack.diffStix.utils.stix_utils import cleanup_values


class JsonGenerator:
    """Generates JSON formatted changelog output from ATT&CK version differences."""

    def __init__(self, diff_stix_instance):
        """Initialize JsonGenerator with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def generate(self) -> dict:
        """Return dict format summarizing detected differences.

        Returns
        -------
        dict
            A dict containing all changes organized by domain and object type
        """
        logger.info("Generating changes info")

        changes_dict = {}
        for domain in self.diff_stix.domains:
            changes_dict[domain] = {}

        for object_type, domains in self.diff_stix.data["changes"].items():
            for domain, sections in domains.items():
                changes_dict[domain][object_type] = {}

                for section, stix_objects in sections.items():
                    groupings = self.diff_stix.get_groupings(
                        object_type=object_type,
                        stix_objects=stix_objects,
                        section=section,
                        domain=domain,
                    )
                    # new_values includes parents & children mixed
                    # (e.g. techniques/sub-techniques, data sources/components)
                    new_values = cleanup_values(groupings=groupings)
                    changes_dict[domain][object_type][section] = new_values

        # always add contributors
        changes_dict["new-contributors"] = []
        sorted_contributors = sorted(self.diff_stix.release_contributors, key=lambda v: v.lower())
        for contributor in sorted_contributors:
            # do not include ATT&CK as contributor
            if contributor == "ATT&CK":
                continue
            changes_dict["new-contributors"].append(contributor)

        return changes_dict
