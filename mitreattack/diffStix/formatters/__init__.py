"""Output generation modules for changelog reports."""

from mitreattack.diffStix.formatters.html_output import (
    get_placard_version_string,
    markdown_to_html,
    write_detailed_html,
)
from mitreattack.diffStix.formatters.layer_output import layers_dict_to_files

__all__ = [
    "get_placard_version_string",
    "markdown_to_html",
    "write_detailed_html",
    "layers_dict_to_files",
]
