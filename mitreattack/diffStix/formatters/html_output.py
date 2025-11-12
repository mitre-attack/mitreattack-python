"""HTML output generation for changelog reports."""

import json
import re
import textwrap

import markdown
from loguru import logger

from mitreattack.diffStix.utils.stix_utils import get_attack_id
from mitreattack.diffStix.utils.version_utils import (
    get_attack_object_version,
    version_increment_is_valid,
)


def get_placard_version_string(stix_object: dict, section: str) -> str:
    """Get the HTML version representation of the ATT&CK STIX object.

    Parameters
    ----------
    stix_object : dict
        An ATT&CK STIX Domain Object (SDO).
    section : str
        Section change type, e.g major_version_change, revocations, etc.

    Returns
    -------
    str
        Final HTML representation of what the version change looks like.
    """
    gray = "#929393"
    red = "#eb6635"
    color = gray

    object_version = get_attack_object_version(stix_obj=stix_object)
    version_display = f"(v{object_version})"

    if section in ["additions", "deprecations", "revocations"]:
        # only display current version
        if not version_increment_is_valid(old_version=None, new_version=object_version, section=section):
            color = red

    elif section == "deletions":
        color = red

    # nothing needs to be added to this statement - it just needs to skip the 'else' clause
    elif section == "patches":
        pass

    else:
        # the "previous_version" key was added in the load_data() function
        old_version = stix_object.get("previous_version")
        if not version_increment_is_valid(old_version=old_version, new_version=object_version, section=section):
            color = red
        version_display = f"(v{old_version}&#8594;v{object_version})"

    return f'<small style="color:{color}">{version_display}</small>'


def markdown_to_html(outfile: str, content: str, diffStix):
    """Convert the markdown string passed in to HTML and store in index.html of indicated output file path.

    Parameters
    ----------
    outfile : str
        File to write HTML for the changelog.
    content : str
        Content to write to the changelog file.
    diffStix : DiffStix
        An instance of a DiffStix object.
    """
    logger.info("Writing HTML to file")
    old_version = diffStix.data["old"]["enterprise-attack"]["attack_release_version"]
    new_version = diffStix.data["new"]["enterprise-attack"]["attack_release_version"]
    if new_version:
        header = f"<h1 style='text-align:center;'>ATT&CK Changes Between v{old_version} and v{new_version}</h1>"
    else:
        header = f"<h1 style='text-align:center;'>ATT&CK Changes Between v{old_version} and new content</h1>"

    # Center content
    html_string = """<div style='max-width: 55em;margin: auto;margin-top:20px;font-family: "Roboto", sans-serif;'>"""
    html_string += "<meta charset='utf-8'>"
    html_string += header
    html_string += markdown.markdown(content, extensions=["toc"])
    html_string += "</div>"

    with open(outfile, "w", encoding="utf-8") as outputfile:
        outputfile.write(html_string)


def write_detailed_html(html_file_detailed: str, diffStix):
    """Write a detailed HTML report of changes between ATT&CK versions.

    Parameters
    ----------
    html_file_detailed : str
        File to write HTML for the detailed changelog.
    diffStix : DiffStix
        An instance of a DiffStix object.
    """
    old_version = diffStix.data["old"]["enterprise-attack"]["attack_release_version"]
    new_version = diffStix.data["new"]["enterprise-attack"]["attack_release_version"]

    if new_version:
        header = f"<h1>ATT&CK Changes Between v{old_version} and v{new_version}</h1>"
    else:
        header = f"<h1>ATT&CK Changes Between v{old_version} and new content</h1>"

    frontmatter = [
        textwrap.dedent(
            """\
        <!DOCTYPE html>
        <html>
            <head>
                <title>ATT&CK Changes</title>
                <meta http-equiv="Content-Type" content="text/html; charset=utf8">
                <style type="text/css">
                    table.diff {font-family:Courier; border:medium;}
                    .diff_header {background-color:#e0e0e0}
                    td.diff_header {text-align:right}
                    .diff_next {background-color:#c0c0c0}
                    .diff_add {background-color:#aaffaa}
                    .diff_chg {background-color:#ffff77}
                    .diff_sub {background-color:#ffaaaa}
                </style>
            </head>
            <body>
        """
        ),
        header,
        markdown.markdown(diffStix.markdown_generator.get_md_key()),
        textwrap.dedent(
            """\
        <table class=diff summary=Legends>
            <tr>
                <td>
                    <table border= summary=Colors>
                        <tr><th>Colors for description field</th></tr>
                        <tr><td class=diff_add>Added</td></tr>
                        <tr><td class=diff_chg>Changed</td></tr>
                        <tr><td class=diff_sub>Deleted</td></tr>
                    </table>
                </td>
            </tr>
        </table>
        <h2>Additional formats</h2>
        <p>These ATT&CK Navigator layer files can be uploaded to ATT&CK Navigator manually.</p>
        <ul>
            <li><a href="layer-enterprise.json">Enterprise changes</a></li>
            <li><a href="layer-mobile.json">Mobile changes</a></li>
            <li><a href="layer-ics.json">ICS changes</a></li>
        </ul>
        <p>This JSON file contains the machine readble output used to create this page: <a href="changelog.json">changelog.json</a></p>
        """
        ),
    ]

    with open(html_file_detailed, "w", encoding="utf-8", errors="xmlcharrefreplace") as file:
        file.writelines(frontmatter)
        lines = []
        for object_type, domain_data in diffStix.data["changes"].items():
            # this is an obnoxious way of determining if there are changes in any of the sections for any of the domains
            if sum([sum(change_types.values(), []) for change_types in domain_data.values()], []):
                lines.append(f"<h2>{diffStix.attack_type_to_title[object_type]}</h2>")
            else:
                continue

            for domain, change_types in domain_data.items():
                if sum(change_types.values(), []):
                    lines.append(f"<h3>{domain}</h3>")
                else:
                    continue

                for change_type, change_data in change_types.items():
                    if change_type == "unchanged":
                        # Not reporting on unchanged STIX objects for detailed changelog
                        continue

                    datastore_version = "old" if change_type == "deletions" else "new"

                    if change_data:
                        lines.append("<details>")
                        lines.append(f"<summary>{diffStix.section_headers[object_type][change_type]}</summary>")

                    for stix_object in change_data:
                        attack_id = get_attack_id(stix_object)
                        object_version = get_attack_object_version(stix_obj=stix_object)

                        if stix_object["type"] == "x-mitre-data-component" or stix_object.get(
                            "x_mitre_is_subtechnique"
                        ):
                            parent_object = diffStix.hierarchy_builder.get_parent_stix_object(
                                stix_object=stix_object, datastore_version=datastore_version, domain=domain
                            )
                            if parent_object:
                                nameplate = f"{parent_object.get('name')}: {stix_object['name']}"
                            else:
                                nameplate = f"{stix_object['name']}"
                        else:
                            nameplate = stix_object["name"]

                        if attack_id:
                            nameplate = f"[{attack_id}] {nameplate}"

                        lines.append("<hr>")
                        lines.append(f"<h4>{nameplate}</h4>")

                        if object_version:
                            lines.append(f"<p><b>Current version</b>: {object_version}</p>")

                        if change_type in ["additions", "revocations", "deprecations", "deletions"]:
                            if stix_object.get("description"):
                                lines.append(
                                    f"<p><b>Description</b>: {markdown.markdown(stix_object['description'])}</p>"
                                )

                        if change_type == "revocations":
                            revoked_by_id = get_attack_id(stix_object["revoked_by"])
                            revoked_by_name = stix_object["revoked_by"]["name"]
                            revoked_by_description = stix_object["revoked_by"]["description"]
                            lines.append("<font color=blue>")
                            lines.append(f"<p>This object has been revoked by [{revoked_by_id}] {revoked_by_name}</p>")
                            lines.append("</font>")
                            if revoked_by_description:
                                lines.append(
                                    f"<p><b>Description for [{revoked_by_id}] {revoked_by_name}</b>: {revoked_by_description}</p>"
                                )

                        version_change = stix_object.get("version_change")
                        if version_change:
                            lines.append(f"<p><b>Version changed from</b>: {version_change}</p>")

                        description_change_table = stix_object.get("description_change_table")
                        if description_change_table:
                            lines.append(description_change_table)

                        if object_type == "techniques":
                            # Mitigations!
                            if stix_object.get("changelog_mitigations"):
                                new_mitigations = stix_object["changelog_mitigations"].get("new")
                                dropped_mitigations = stix_object["changelog_mitigations"].get("dropped")
                                if new_mitigations:
                                    lines.append("<p><b>New Mitigations</b>:</p>")
                                    lines.append("<ul>")
                                    for mitigation in new_mitigations:
                                        lines.append(f"  <li>{mitigation}</li>")
                                    lines.append("</ul>")
                                if dropped_mitigations:
                                    lines.append("<p><b>Dropped Mitigations</b>:</p>")
                                    lines.append("<ul>")
                                    for mitigation in dropped_mitigations:
                                        lines.append(f"  <li>{mitigation}</li>")
                                    lines.append("</ul>")

                            # Detections!
                            if stix_object.get("changelog_datacomponent_detections"):
                                new_detections = stix_object["changelog_datacomponent_detections"].get("new")
                                dropped_detections = stix_object["changelog_datacomponent_detections"].get("dropped")
                                if new_detections:
                                    lines.append("<p><b>New Detections (Data Components -> Technique)</b>:</p>")
                                    lines.append("<ul>")
                                    for detection in new_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")
                                if dropped_detections:
                                    lines.append("<p><b>Dropped Detections (Data Components -> Technique)</b>:</p>")
                                    lines.append("<ul>")
                                    for detection in dropped_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")
                            if stix_object.get("changelog_detectionstrategy_detections"):
                                new_detections = stix_object["changelog_detectionstrategy_detections"].get("new")
                                dropped_detections = stix_object["changelog_detectionstrategy_detections"].get(
                                    "dropped"
                                )
                                if new_detections:
                                    lines.append("<p><b>New Detections (Detection Strategies -> Technique)</b>:</p>")
                                    lines.append("<ul>")
                                    for detection in new_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")
                                if dropped_detections:
                                    lines.append(
                                        "<p><b>Dropped Detections (Detection Strategies -> Technique)</b>:</p>"
                                    )
                                    lines.append("<ul>")
                                    for detection in dropped_detections:
                                        lines.append(f"  <li>{detection}</li>")
                                    lines.append("</ul>")

                        detailed_diff = json.loads(stix_object.get("detailed_diff", "{}"))
                        if detailed_diff:
                            lines.append("<details>")
                            lines.append("<summary>Details</summary>")
                            table_inline_css = "style='border: 1px solid black;border-collapse: collapse;'"

                            # the deepdiff library displays differences with a prefix of:
                            # root['<top-level-key-we-care-about>']
                            regex = r"^root\['(?P<top_stix_key>[^\']*)'\](?P<the_rest>.*)$"
                            for detailed_change_type, detailed_changes in detailed_diff.items():
                                lines.append(f"<table {table_inline_css}>")
                                lines.append(f"<caption>{detailed_change_type}</caption>")
                                lines.append("<thead><tr>")
                                lines.append(f"<th {table_inline_css}>STIX Field</th>")
                                lines.append(f"<th {table_inline_css}>Old value</th>")
                                lines.append(f"<th {table_inline_css}>New Value</th>")
                                lines.append("</tr></thead>")
                                lines.append("<tbody>")

                                if detailed_change_type == "values_changed":
                                    for detailed_change, values in detailed_changes.items():
                                        matches = re.search(regex, detailed_change)
                                        if matches:
                                            top_stix_key = matches.group("top_stix_key")
                                            the_rest = matches.group("the_rest")
                                        else:
                                            continue
                                        stix_field = f"{top_stix_key}{the_rest}"

                                        old_value = values["old_value"]
                                        new_value = values["new_value"]
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "iterable_item_added":
                                    for detailed_change, new_value in detailed_changes.items():
                                        match = re.search(regex, detailed_change)
                                        if not match:
                                            continue
                                        stix_field = match.group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "iterable_item_removed":
                                    for detailed_change, old_value in detailed_changes.items():
                                        match = re.search(regex, detailed_change)
                                        if not match:
                                            continue
                                        stix_field = match.group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "dictionary_item_added":
                                    for detailed_change, new_value in detailed_changes.items():
                                        match = re.search(regex, detailed_change)
                                        if not match:
                                            continue
                                        stix_field = match.group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append(f"<td {table_inline_css}>{new_value}</td>")
                                        lines.append("</tr>")

                                elif detailed_change_type == "dictionary_item_removed":
                                    for detailed_change, old_value in detailed_changes.items():
                                        match = re.search(regex, detailed_change)
                                        if not match:
                                            continue
                                        stix_field = match.group("top_stix_key")
                                        lines.append("<tr>")
                                        lines.append(f"<td {table_inline_css}>{stix_field}</td>")
                                        lines.append(f"<td {table_inline_css}>{old_value}</td>")
                                        lines.append(f"<td {table_inline_css}></td>")
                                        lines.append("</tr>")

                                else:
                                    lines.append(f"<h5>{detailed_change_type}</h5>")
                                    lines.append("<ul>")
                                    for detailed_change in detailed_changes:
                                        lines.append(f"<li>{detailed_change}</li>")
                                    lines.append("</ul>")

                                lines.append("</tbody></table>")
                            lines.append("</details>")

                    if change_data:
                        lines.append("</details>")

        lines.append(
            """
            </body>
        </html>
        """
        )

        file.writelines(lines)
