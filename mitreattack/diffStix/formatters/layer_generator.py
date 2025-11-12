"""ATT&CK Navigator layer output generator."""

import datetime

from loguru import logger


class LayerGenerator:
    """Generates ATT&CK Navigator layer JSON from ATT&CK version differences."""

    def __init__(self, diff_stix_instance):
        """Initialize LayerGenerator with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def generate(self) -> dict:
        """Return ATT&CK Navigator layers in dict format summarizing detected differences.

        Returns
        -------
        dict
            A dict mapping domain to its layer dict
        """
        logger.info("Generating ATT&CK Navigator layers")

        colors = {
            "additions": "#a1d99b",  # granny smith apple
            "major_version_changes": "#fcf3a2",  # yellow-ish
            "minor_version_changes": "#c7c4e0",  # light periwinkle
            "other_version_changes": "#B5E5CF",  # mint
            "patches": "#B99095",  # mauve
            "deletions": "#ff00e1",  # hot magenta
            "revocations": "#ff9000",  # dark orange
            "deprecations": "#ff6363",  # bittersweet red
            "unchanged": "#ffffff",  # white
        }

        layers = {}
        thedate = datetime.datetime.today().strftime("%B %Y")
        # for each layer file in the domains mapping
        for domain in self.diff_stix.domains:
            logger.debug(f"Generating ATT&CK Navigator layer for domain: {domain}")
            # build techniques list
            techniques = []
            for section, technique_stix_objects in self.diff_stix.data["changes"]["techniques"][domain].items():
                if section == "revocations" or section == "deprecations":
                    continue

                for technique in technique_stix_objects:
                    problem_detected = False
                    if "kill_chain_phases" not in technique:
                        logger.error(f"{technique['id']}: technique missing a tactic!! {technique['name']}")
                        problem_detected = True
                    if "external_references" not in technique:
                        logger.error(f"{technique['id']}: technique missing external references!! {technique['name']}")
                        problem_detected = True

                    if problem_detected:
                        continue

                    for phase in technique["kill_chain_phases"]:
                        techniques.append(
                            {
                                "techniqueID": technique["external_references"][0]["external_id"],
                                "tactic": phase["phase_name"],
                                "enabled": True,
                                "color": colors[section],
                                # trim the 's' off end of word
                                "comment": section[:-1] if section != "unchanged" else section,
                            }
                        )

            legendItems = []
            for section, description in self.diff_stix.section_descriptions.items():
                legendItems.append({"color": colors[section], "label": f"{section}: {description}"})

            # build layer structure
            layer_json = {
                "versions": {
                    "layer": "4.5",
                    "navigator": "5.0.0",
                    "attack": self.diff_stix.data["new"][domain]["attack_release_version"],
                },
                "name": f"{thedate} {self.diff_stix.domain_to_domain_label[domain]} Updates",
                "description": f"{self.diff_stix.domain_to_domain_label[domain]} updates for the {thedate} release of ATT&CK",
                "domain": domain,
                "techniques": techniques,
                "sorting": 0,
                "hideDisabled": False,
                "legendItems": legendItems,
                "showTacticRowBackground": True,
                "tacticRowBackground": "#205b8f",
                "selectTechniquesAcrossTactics": True,
            }
            layers[domain] = layer_json

        return layers
