"""Layer file output generation for ATT&CK Navigator."""

import json
from pathlib import Path

from loguru import logger


def layers_dict_to_files(outfiles, layers):
    """Print the layers dict passed in to layer files."""
    logger.info("Writing ATT&CK Navigator layers to JSON files")

    # write each layer to separate files
    if "enterprise-attack" in layers:
        enterprise_attack_layer_file = outfiles[0]
        Path(enterprise_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["enterprise-attack"], open(enterprise_attack_layer_file, "w"), indent=4)

    if "mobile-attack" in layers:
        mobile_attack_layer_file = outfiles[1]
        Path(mobile_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["mobile-attack"], open(mobile_attack_layer_file, "w"), indent=4)

    if "ics-attack" in layers:
        ics_attack_layer_file = outfiles[2]
        Path(ics_attack_layer_file).parent.mkdir(parents=True, exist_ok=True)
        json.dump(layers["ics-attack"], open(ics_attack_layer_file, "w"), indent=4)
