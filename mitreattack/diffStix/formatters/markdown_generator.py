"""Markdown changelog output generator."""

import textwrap

from loguru import logger

from mitreattack.diffStix.formatters.html_output import get_placard_version_string
from mitreattack.diffStix.utils.constants import (
    ATTACK_TYPE_TO_TITLE,
    DOMAIN_TO_LABEL,
    SECTION_DESCRIPTIONS,
    get_section_headers,
)
from mitreattack.diffStix.utils.url_utils import get_relative_data_component_url, get_relative_url_from_stix


class MarkdownGenerator:
    """Generates markdown formatted changelog output from ATT&CK version differences."""

    def __init__(self, diff_stix_instance):
        """Initialize MarkdownGenerator with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def generate(self) -> str:
        """Generate complete markdown changelog string.

        Returns
        -------
        str
            Full markdown string summarizing detected differences
        """
        logger.info("Generating markdown output")
        content = ""

        # Add contributors if requested
        if self.diff_stix.include_contributors:
            content += self.diff_stix.get_contributor_section()
            content += "\n"

        # Add statistics section for the new version
        logger.info("Generating statistics section")
        stats_section = self.diff_stix.get_statistics_section(datastore_version="new")
        content += stats_section

        if self.diff_stix.show_key:
            key_content = self.get_md_key()
            content += f"{key_content}\n"

        content += "## Table of Contents\n\n"
        content += "[TOC]\n\n"

        for object_type in self.diff_stix.types:
            domains = ""

            for domain in self.diff_stix.data["changes"][object_type]:
                # e.g "Enterprise"
                next_domain = f"### {DOMAIN_TO_LABEL[domain]}\n\n"

                # Skip mobile section for data sources
                if domain == "mobile-attack" and object_type == "datasource":
                    logger.debug("Skipping - ATT&CK for Mobile does not support data sources")
                    next_domain += "ATT&CK for Mobile does not support data sources\n\n"
                    continue

                domain_sections = ""
                section_headers = get_section_headers(object_type)

                for section, stix_objects in self.diff_stix.data["changes"][object_type][domain].items():
                    header = f"#### {section_headers[section]}"
                    if stix_objects:
                        groupings = self.diff_stix.hierarchy_builder.get_groupings(
                            object_type=object_type,
                            stix_objects=stix_objects,
                            section=section,
                            domain=domain,
                        )
                        section_items = self.get_markdown_section_data(
                            groupings=groupings, section=section, domain=domain
                        )
                        domain_sections += f"{header}\n\n{section_items}\n"

                # Add domain sections
                if domain_sections != "":
                    domains += f"{next_domain}{domain_sections}"

            # e.g "Techniques"
            if domains != "":
                content += f"## {ATTACK_TYPE_TO_TITLE[object_type]}\n\n{domains}"

        return content

    def get_markdown_section_data(self, groupings, section: str, domain: str) -> str:
        """Parse a list of STIX objects in a section and return a string for the whole section.

        Parameters
        ----------
        groupings : list
            List of grouped STIX objects
        section : str
            Section change type (e.g., major_version_change, revocations)
        domain : str
            ATT&CK domain (e.g., "enterprise-attack")

        Returns
        -------
        str
            Formatted markdown string for the section
        """
        section_string = ""
        placard_string = ""

        for grouping in groupings:
            if grouping["parentInSection"]:
                placard_string = self.placard(stix_object=grouping["parent"], section=section, domain=domain)
                section_string += f"* {placard_string}\n"

            for child in sorted(grouping["children"], key=lambda child: child["name"]):
                placard_string = self.placard(stix_object=child, section=section, domain=domain)

                if grouping["parentInSection"]:
                    section_string += f"  * {placard_string}\n"
                else:
                    section_string += f"* {grouping['parent']['name']}: {placard_string}\n"

        return section_string

    def placard(self, stix_object: dict, section: str, domain: str) -> str:
        """Get a section list item for the given STIX Domain Object (SDO) according to section type.

        Parameters
        ----------
        stix_object : dict
            An ATT&CK STIX Domain Object (SDO)
        section : str
            Section change type (e.g., major_version_change, revocations)
        domain : str
            ATT&CK domain (e.g., "enterprise-attack")

        Returns
        -------
        str
            Final return string to be displayed in the Changelog
        """
        datastore_version = "old" if section == "deletions" else "new"
        placard_string = ""

        if section == "deletions":
            placard_string = stix_object["name"]

        elif section == "revocations":
            revoker = stix_object["revoked_by"]

            if revoker.get("x_mitre_is_subtechnique"):
                parent_object = self.diff_stix.get_parent_stix_object(
                    stix_object=revoker, datastore_version=datastore_version, domain=domain
                )
                parent_name = parent_object.get("name", "ERROR NO PARENT")
                relative_url = get_relative_url_from_stix(stix_object=revoker)
                revoker_link = f"{self.diff_stix.site_prefix}/{relative_url}"
                placard_string = (
                    f"{stix_object['name']} (revoked by {parent_name}: [{revoker['name']}]({revoker_link}))"
                )

            elif revoker["type"] == "x-mitre-data-component":
                parent_object = self.diff_stix.get_parent_stix_object(
                    stix_object=revoker, datastore_version=datastore_version, domain=domain
                )
                if parent_object:
                    parent_name = parent_object.get("name", "ERROR NO PARENT")
                    relative_url = get_relative_data_component_url(datasource=parent_object, datacomponent=stix_object)
                    revoker_link = f"{self.diff_stix.site_prefix}/{relative_url}"
                    placard_string = (
                        f"{stix_object['name']} (revoked by {parent_name}: [{revoker['name']}]({revoker_link}))"
                    )
                else:
                    # No parent datasource available — fall back to a plain-text representation
                    placard_string = f"{stix_object['name']} (revoked by {revoker['name']})"

            else:
                relative_url = get_relative_url_from_stix(stix_object=revoker)
                revoker_link = f"{self.diff_stix.site_prefix}/{relative_url}"
                placard_string = f"{stix_object['name']} (revoked by [{revoker['name']}]({revoker_link}))"

        else:
            if stix_object["type"] == "x-mitre-data-component":
                parent_object = self.diff_stix.get_parent_stix_object(
                    stix_object=stix_object, datastore_version=datastore_version, domain=domain
                )
                if parent_object:
                    relative_url = get_relative_data_component_url(datasource=parent_object, datacomponent=stix_object)
                    placard_string = f"[{stix_object['name']}]({self.diff_stix.site_prefix}/{relative_url})"
                else:
                    # No parent datasource available — display datacomponent name as plain text
                    placard_string = stix_object["name"]

            else:
                relative_url = get_relative_url_from_stix(stix_object=stix_object)
                placard_string = f"[{stix_object['name']}]({self.diff_stix.site_prefix}/{relative_url})"

        version_string = get_placard_version_string(stix_object=stix_object, section=section)
        full_placard_string = f"{placard_string} {version_string}"
        return full_placard_string

    def get_md_key(self) -> str:
        """Create string describing each type of difference (change, addition, etc).

        Returns
        -------
        str
            Key for change types used in Markdown output
        """
        # End first line with \ to avoid the empty line from dedent()
        key = textwrap.dedent(
            f"""\
            ## Key

            * New objects: {SECTION_DESCRIPTIONS["additions"]}
            * Major version changes: {SECTION_DESCRIPTIONS["major_version_changes"]}
            * Minor version changes: {SECTION_DESCRIPTIONS["minor_version_changes"]}
            * Other version changes: {SECTION_DESCRIPTIONS["other_version_changes"]}
            * Patches: {SECTION_DESCRIPTIONS["patches"]}
            * Object revocations: {SECTION_DESCRIPTIONS["revocations"]}
            * Object deprecations: {SECTION_DESCRIPTIONS["deprecations"]}
            * Object deletions: {SECTION_DESCRIPTIONS["deletions"]}
            """
        )

        return key
