"""Custom JSON encoder for ATT&CK changelog generation."""

import json

from mitreattack.diffStix.utils.version_utils import AttackObjectVersion


# TODO: Implement a custom decoder as well. Possible solution at this link
# https://alexisgomes19.medium.com/custom-json-encoder-with-python-f52c91b48cd2
class AttackChangesEncoder(json.JSONEncoder):
    """Custom JSON encoder for changes made to ATT&CK between releases."""

    def default(self, o):
        """Handle custom object types so they can be serialized to JSON."""
        if isinstance(o, AttackObjectVersion):
            return str(o)

        return json.JSONEncoder.default(self, o)
