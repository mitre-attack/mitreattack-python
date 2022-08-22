import copy
import datetime
import re
from itertools import chain

import numpy as np
import pandas as pd
from loguru import logger
from stix2 import Filter, MemoryStore
from tqdm import tqdm

from mitreattack.constants import MITRE_ATTACK_ID_SOURCE_NAMES


# Lookup module for Platforms - each matrix has a list of possible platforms, and each platform with multiple
#   subplatforms has a corresponding entry. This allows for a pseudo-recursive lookup of subplatforms, as the presence
#   of a platform at the top level of this lookup indicates the existence of subplatforms.
MATRIX_PLATFORMS_LOOKUP = {
    "enterprise-attack": [
        "PRE",
        "Windows",
        "macOS",
        "Linux",
        "Cloud",
        "Office 365",
        "Azure AD",
        "Google Workspace",
        "SaaS",
        "IaaS",
        "Network",
        "Containers",
    ],
    "mobile-attack": ["Android", "iOS"],
    "Cloud": ["Office 365", "Azure AD", "Google Workspace", "SaaS", "IaaS"],
    "ics-attack": [
        "Field Controller/RTU/PLC/IED",
        "Safety Instrumented System/Protection Relay",
        "Control Server",
        "Input/Output Server",
        "Windows",
        "Human-Machine Interface",
        "Engineering Workstation",
        "Data Historian",
    ],
}

TITLE_EXCLUSIONS = ["and"]


def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source."""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects,
        )
    )


def filter_platforms(stix_objects, platforms):
    """Filter out any objects that don't have a matching platform to one in 'platforms'."""
    if not platforms:
        return stix_objects

    return list(
        filter(
            lambda x: any(
                platform.lower() in [y.lower() for y in x.get("x_mitre_platforms", [])] for platform in platforms
            ),
            stix_objects,
        )
    )


def format_date(date):
    """Given a date string, return it formatted as %d %B %Y."""
    if isinstance(date, str):
        date = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
    return "{} {} {}".format(date.strftime("%d"), date.strftime("%B"), date.strftime("%Y"))


def get_citations(objects):
    """Given a list of STIX objects, return a pandas dataframe for the citations on the objects."""
    citations = []
    for sdo in objects:
        if "external_references" in sdo:
            for ref in sdo["external_references"]:
                if (
                    "external_id" not in ref
                    and "description" in ref
                    and not ref["description"].startswith("(Citation: ")
                ):
                    citation = {
                        "reference": ref["source_name"],
                        "citation": ref["description"],
                    }
                    if "url" in ref:
                        citation["url"] = ref["url"]

                    citations.append(citation)

    return pd.DataFrame(citations).drop_duplicates(subset="reference", ignore_index=True)


def parseBaseStix(sdo):
    """Given an SDO, return a dict of field names:values that are common across all ATT&CK STIX types."""
    row = {}
    url = None
    if sdo.get("external_references"):
        if sdo["external_references"][0]["source_name"] in MITRE_ATTACK_ID_SOURCE_NAMES:
            row["ID"] = sdo["external_references"][0]["external_id"]
            url = sdo["external_references"][0]["url"]
    if "name" in sdo:
        row["name"] = sdo["name"]
    if "description" in sdo:
        row["description"] = sdo["description"]
    if url:
        row["url"] = url
    if "created" in sdo:
        row["created"] = format_date(sdo["created"])
    if "modified" in sdo:
        row["last modified"] = format_date(sdo["modified"])
    if "x_mitre_version" in sdo:
        row["version"] = sdo["x_mitre_version"]
    if "x_mitre_contributors" in sdo:
        row["contributors"] = "; ".join(sorted(sdo["x_mitre_contributors"]))
    return row


def techniquesToDf(src, domain):
    """Parse STIX techniques from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    techniques = src.query([Filter("type", "=", "attack-pattern")])
    techniques = remove_revoked_deprecated(techniques)
    technique_rows = []

    all_sub_techniques = src.query(
        [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "subtechnique-of"),
        ]
    )
    all_sub_techniques = MemoryStore(stix_data=all_sub_techniques)

    for technique in tqdm(techniques, desc="parsing techniques"):
        # get parent technique if sub-technique
        subtechnique = "x_mitre_is_subtechnique" in technique and technique["x_mitre_is_subtechnique"]
        if subtechnique:
            subtechnique_of = all_sub_techniques.query([Filter("source_ref", "=", technique["id"])])[0]
            parent = src.get(subtechnique_of["target_ref"])

        # base STIX properties
        row = parseBaseStix(technique)

        # sub-technique properties
        if "kill_chain_phases" not in technique:
            logger.error(f"Skipping {technique['external_references'][0]['external_id']} [{technique['id']}] because it does't have kill chain phases")
            continue
        tactic_shortnames = list(map(lambda kcp: kcp["phase_name"], technique["kill_chain_phases"]))
        tactics = list(
            map(
                lambda t: " ".join([x.title() if x not in TITLE_EXCLUSIONS else x for x in t.split("-")]),
                tactic_shortnames,
            )
        )
        row["tactics"] = ", ".join(sorted(tactics))

        if "x_mitre_detection" in technique:
            row["detection"] = technique["x_mitre_detection"]
        if "x_mitre_platforms" in technique:
            row["platforms"] = ", ".join(sorted(technique["x_mitre_platforms"]))

        # domain specific fields -- ICS + Enterprise
        if domain in ["enterprise-attack", "ics-attack"]:
            if "x_mitre_data_sources" in technique:
                row["data sources"] = ", ".join(sorted(technique["x_mitre_data_sources"]))

        # domain specific fields -- enterprise
        if domain == "enterprise-attack":
            row["is sub-technique"] = subtechnique
            if subtechnique:
                row["name"] = f"{parent['name']}: {technique['name']}"
                row["sub-technique of"] = parent["external_references"][0]["external_id"]

            if "x_mitre_system_requirements" in technique:
                row["system requirements"] = ", ".join(sorted(technique["x_mitre_system_requirements"]))
            if "x_mitre_permissions_required" in technique:
                row["permissions required"] = ", ".join(
                    sorted(technique["x_mitre_permissions_required"], key=str.lower)
                )
            if "x_mitre_effective_permissions" in technique:
                row["effective permissions"] = ", ".join(
                    sorted(technique["x_mitre_effective_permissions"], key=str.lower)
                )

            if "defense-evasion" in tactic_shortnames and "x_mitre_defense_bypassed" in technique:
                row["defenses bypassed"] = ", ".join(sorted(technique["x_mitre_defense_bypassed"]))
            if "execution" in tactic_shortnames and "x_mitre_remote_support" in technique:
                row["supports remote"] = technique["x_mitre_remote_support"]
            if "impact" in tactic_shortnames and "x_mitre_impact_type" in technique:
                row["impact type"] = ", ".join(sorted(technique["x_mitre_impact_type"]))
            capec_refs = list(
                filter(
                    lambda ref: ref["source_name"] == "capec",
                    technique["external_references"],
                )
            )
            if capec_refs:
                row["CAPEC ID"] = ", ".join([x["external_id"] for x in capec_refs])

        # domain specific fields -- mobile
        elif domain == "mobile-attack":
            if "x_mitre_tactic_type" in technique:
                row["tactic type"] = ", ".join(sorted(technique["x_mitre_tactic_type"]))
            mtc_refs = list(
                filter(
                    lambda ref: ref["source_name"] == "NIST Mobile Threat Catalogue",
                    technique["external_references"],
                )
            )
            if mtc_refs:
                row["MTC ID"] = mtc_refs[0]["external_id"]

        technique_rows.append(row)

    citations = get_citations(techniques)
    dataframes = {
        "techniques": pd.DataFrame(technique_rows).sort_values("name"),
    }
    # add relationships
    codex = relationshipsToDf(src, relatedType="technique")
    dataframes.update(codex)
    # add relationship references
    dataframes["techniques"][f"relationship citations"] = _get_relationship_citations(dataframes["techniques"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def tacticsToDf(src, domain):
    """Parse STIX tactics from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    tactics = src.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = remove_revoked_deprecated(tactics)

    tactic_rows = []
    for tactic in tqdm(tactics, desc="parsing mitigations"):
        tactic_rows.append(parseBaseStix(tactic))

    citations = get_citations(tactics)
    dataframes = {
        "tactics": pd.DataFrame(tactic_rows).sort_values("name"),
    }
    if not citations.empty:
        dataframes["citations"] = citations.sort_values("reference")

    return dataframes


def sourcesToDf(src, domain):
    """Parse STIX Data Sources and their Data components from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    data = list(
        chain.from_iterable(  # software are the union of the tool and malware types
            src.query(f)
            for f in [
                Filter("type", "=", "x-mitre-data-component"),
                Filter("type", "=", "x-mitre-data-source"),
            ]
        )
    )
    if data:
        refined = remove_revoked_deprecated(data)
        data_object_rows = []
        source_lookup = dict()
        for x in refined:
            if x["type"] == "x-mitre-data-source":
                source_lookup[x["id"]] = x["name"]
        for data_object in tqdm(refined, desc="parsing data sources"):
            # add common STIx fields
            row = parseBaseStix(data_object)
            # add software-specific fields
            if "x_mitre_platforms" in data_object:
                row["platforms"] = ", ".join(sorted(data_object["x_mitre_platforms"]))
            if "x_mitre_collection_layers" in data_object:
                row["collection layers"] = ", ".join(sorted(data_object["x_mitre_collection_layers"]))
            if "x_mitre_aliases" in data_object:
                row["aliases"] = ", ".join(sorted(data_object["x_mitre_aliases"][1:]))
            if data_object["type"] == "x-mitre-data-component":
                row["name"] = f"{source_lookup[data_object['x_mitre_data_source_ref']]}: {data_object['name']}"
                row["type"] = "datacomponent"
            else:
                row["type"] = "datasource"
            if "description" in data_object:
                row["description"] = data_object["description"]
            data_object_rows.append(row)

        citations = get_citations(refined)
        tempa = pd.DataFrame(data_object_rows).sort_values("name")
        dataframes = {
            "datasources": tempa.reindex(
                columns=[
                    "name",
                    "ID",
                    "description",
                    "collection layers",
                    "platforms",
                    "created",
                    "modified",
                    "type",
                    "version",
                    "url",
                    "contributors",
                ]
            ),
        }
        # add relationships
        dataframes.update(relationshipsToDf(src, relatedType="datasource"))
        # add/merge citations
        if not citations.empty:
            if "citations" in dataframes:  # append to existing citations from references
                dataframes["citations"] = pd.concat([dataframes["citations"], citations])
            else:  # add citations
                dataframes["citations"] = citations

            dataframes["citations"].sort_values("reference")

        return dataframes
    else:
        print(f"[WARNING] (sourceToDf) - No data components or data sources found for domain {domain}. Skipping...")


def softwareToDf(src, domain):
    """Parse STIX software from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    software = list(
        chain.from_iterable(  # software are the union of the tool and malware types
            src.query(f) for f in [Filter("type", "=", "tool"), Filter("type", "=", "malware")]
        )
    )
    software = remove_revoked_deprecated(software)
    software_rows = []
    for soft in tqdm(software, desc="parsing software"):
        # add common STIx fields
        row = parseBaseStix(soft)
        # add software-specific fields
        if "x_mitre_platforms" in soft:
            row["platforms"] = ", ".join(sorted(soft["x_mitre_platforms"]))
        if "x_mitre_aliases" in soft:
            row["aliases"] = ", ".join(sorted(soft["x_mitre_aliases"][1:]))
        row["type"] = soft["type"]  # malware or tool

        software_rows.append(row)

    citations = get_citations(software)
    dataframes = {
        "software": pd.DataFrame(software_rows).sort_values("name"),
    }
    # add relationships
    codex = relationshipsToDf(src, relatedType="software")
    dataframes.update(codex)
    # add relationship references
    dataframes["software"][f"relationship citations"] = _get_relationship_citations(dataframes["software"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def groupsToDf(src, domain):
    """Parse STIX groups from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    groups = src.query([Filter("type", "=", "intrusion-set")])
    groups = remove_revoked_deprecated(groups)
    group_rows = []
    for group in tqdm(groups, desc="parsing groups"):
        row = parseBaseStix(group)
        # add group aliases
        if "aliases" in group:
            associated_groups = []
            associated_group_citations = []
            for alias in sorted(group["aliases"][1:]):
                # find the reference for the alias
                associated_groups.append(alias)
                for ref in group["external_references"]:
                    if ref["source_name"] == alias:
                        associated_group_citations.append(ref["description"])
                        break
                        # aliases.append(alias)
            row["associated groups"] = ", ".join(associated_groups)
            row["associated groups citations"] = ", ".join(associated_group_citations)

        group_rows.append(row)

    citations = get_citations(groups)
    dataframes = {
        "groups": pd.DataFrame(group_rows).sort_values("name"),
    }
    # add relationships
    codex = relationshipsToDf(src, relatedType="group")
    dataframes.update(codex)
    # add relationship references
    dataframes["groups"][f"relationship citations"] = _get_relationship_citations(dataframes["groups"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def mitigationsToDf(src, domain):
    """Parse STIX mitigations from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    mitigations = src.query([Filter("type", "=", "course-of-action")])
    mitigations = remove_revoked_deprecated(mitigations)
    mitigation_rows = []
    for mitigation in tqdm(mitigations, desc="parsing mitigations"):
        mitigation_rows.append(parseBaseStix(mitigation))

    citations = get_citations(mitigations)
    dataframes = {
        "mitigations": pd.DataFrame(mitigation_rows).sort_values("name"),
    }
    # add relationships
    codex = relationshipsToDf(src, relatedType="mitigation")
    dataframes.update(codex)
    # add relationship references
    dataframes["mitigations"]["relationship citations"] = _get_relationship_citations(dataframes["mitigations"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


class CellRange:
    """Helper class for handling ranges of cells in a spreadsheet. Note: not 0-indexed, row and cols start at 1.

    Data is optional argument for data to store in the cellrange in the case of merged ranges
    format is a dict {name, format} for the XlsxWriter style. Formats of the same name will not be defined multiple
    times to the worksheet; only the first definition will be used
    """

    def __init__(self, leftCol, rightCol, topRow, bottomRow, data=None, format=None):
        self.leftCol = leftCol
        self.rightCol = rightCol
        self.topRow = topRow
        self.bottomRow = bottomRow
        self.data = data
        self.format = format

    def to_excel_format(self):
        """Return the range in excel format, e.g A4:C7."""
        return f"{self._loc_to_excel(self.topRow, self.leftCol)}:{self._loc_to_excel(self.bottomRow, self.rightCol)}"

    def _loc_to_excel(self, row, col):
        """Convert given row and column number to an Excel-style cell name. Note: not 0-indexed."""
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = []
        while col:
            col, rem = divmod(col - 1, 26)
            result[:0] = letters[rem]
        return "".join(result) + str(row)


def build_technique_and_sub_columns(src, techniques, columns, merge_data_handle, matrix_grid_handle, tactic_name, platform=None):
    """Build technique and subtechnique columns for a given matrix and attach them to the appropriate object listings.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param techniques: List of technique stix objects belong in this tactic column
    :param columns: Existing columns in this matrix (used for placement)
    :param merge_data_handle: Handle to the 'merge' data object for this matrix
    :param matrix_grid_handle: Handle to the 2D grid array being constructed for the matrix (technique and subtechnique
                                columns will be appended here)
    :param tactic_name: The name of the corresponding tactic for this column
    :param platform: [Optional] The name of a platform to filter subtechniques by

    :return: Nothing (meta - modifies the passed in merge_data_handle and matrix_grid_handle objects)
    """
    techniques_column = []
    subtechniques_column = []

    all_sub_techniques = src.query(
        [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "subtechnique-of"),
        ]
    )
    all_sub_techniques = MemoryStore(stix_data=all_sub_techniques)

    for technique in techniques:
        techniques_column.append(technique["name"])
        # sub-technique relationships
        subtechnique_ofs = all_sub_techniques.query([Filter("target_ref", "=", technique["id"])])
        if len(subtechnique_ofs) > 0:  # if there are sub-techniques on the tactic
            technique_top = len(techniques_column) + 1  # top of row range to merge
            # get sub-techniques
            subtechniques = [src.get(rel["source_ref"]) for rel in subtechnique_ofs]
            if platform:
                subtechniques = filter_platforms(
                    subtechniques,
                    MATRIX_PLATFORMS_LOOKUP[platform] if platform in MATRIX_PLATFORMS_LOOKUP else [platform]
                )

            subtechniques = remove_revoked_deprecated(subtechniques)
            subtechniques = sorted(subtechniques, key=lambda x: x["name"])
            for i in range(len(subtechniques)):  # for each sub-technique
                if i != 0:
                    techniques_column.append("")  # first sub-technique is parallel to the technique in the layout
                subtechniques_column.append(subtechniques[i]["name"])
            technique_bottom = len(techniques_column) + 1  # bottom of row range to merge
            if technique_top != technique_bottom:  # more than 1 sub-technique
                merge_data_handle.append(
                    CellRange(  # merge technique portion of cell group
                        len(columns),
                        len(columns),
                        technique_top,
                        technique_bottom,
                        data=technique["name"],
                        format={  # format of the merged range
                            "name": "supertechnique",
                            "format": {
                                "valign": "vcenter",
                                "text_wrap": 1,
                                "shrink": 1,
                            },
                        },
                    )
                )
        else:  # no sub-techniques; add empty cell parallel to technique
            subtechniques_column.append("")
    # end adding techniques and sub-techniques to column

    matrix_grid_handle.append(techniques_column)  # add technique column to grid

    if len(list(filter(lambda x: x != "", subtechniques_column))) > 0:  # if there are sub-techniques for the tactic
        matrix_grid_handle.append(subtechniques_column)  # add sub-technique sub-column
        columns.append("")  # add empty tactic header for the sub-column
        merge_data_handle.append(  # merge tactic column header with the sub-column header that was just appended
            CellRange(
                len(columns) - 1,
                len(columns),
                1,
                1,
                data=tactic_name,
                format={  # tactic header formatting
                    "name": "tacticHeader",
                    "format": {
                        "bold": 1,
                        "border": 1,
                        "font_size": 14,
                        "align": "center",
                        "shrink": 1,
                    },
                },
            )
        )


def build_parsed_DF_matrix(matrix_grid, columns, merge, parsed_dict):
    """Build the DF matrix object.

    :param matrix_grid: 2D array of the matrix to build
    :param columns: Column headers
    :param merge: Any applicable cell merge ranges and styles
    :param parsed_dict: Dictionary containing name and description for the matrix
    :return: { matrix, name, description, merge, border } where
        matrix is a pandas dataframe of the matrix
        name is the name of the matrix
        description is the description of the matrix
        merge is a list of CellRange objects that need to be merged for formatting of the sub-techniques in the matrix
        columns is the number of columns in the data
    """
    parsed = copy.deepcopy(parsed_dict)
    # reshape array so that pandas consumes it properly
    matrix_grid = np.flip(np.rot90(matrix_grid), 0)
    # create dataframe for array
    df = pd.DataFrame(matrix_grid, columns=columns)

    # Set additional data for the matrix
    parsed["matrix"] = df  # actual dataframe
    parsed["merge"] = merge  # merge ranges and associated styles
    parsed["columns"] = len(columns)  # number of columns with data
    return parsed


def matricesToDf(src, domain):
    """Parse STIX matrices from the given data and return parsed matrix structures

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :returns: [{ matrix, name, description, merge, border }, ... ] where
        matrix is a pandas dataframe of the matrix
        name is the name of the matrix
        description is the description of the matrix
        merge is a list of CellRange objects that need to be merged for formatting of the sub-techniques in the matrix
        columns is the number of columns in the data
    """
    matrices = src.query([Filter("type", "=", "x-mitre-matrix")])
    matrices = remove_revoked_deprecated(matrices)
    matrices_parsed = []
    sub_matrices_parsed = []

    for matrix in tqdm(matrices, desc="parsing matrices"):
        sub_matrices_grid = dict()
        sub_matrices_merges = dict()
        sub_matrices_columns = dict()
        for entry in MATRIX_PLATFORMS_LOOKUP[domain]:
            sub_matrices_grid[entry] = []
            sub_matrices_merges[entry] = []
            sub_matrices_columns[entry] = []

        parsed = {
            "name": matrix["name"] if len(matrices) == 1 else f"{domain.split('-')[0].capitalize()} {matrix['name']}",
            "description": matrix["description"],
        }

        matrix_grid = []  # matrix layout in 2d array
        merge = []  # list of CellRange objects to merge later

        columns = []  # column names
        for tactic_ref in tqdm(matrix["tactic_refs"], desc="processing matrix tactics"):
            tactic = src.get(tactic_ref)
            columns.append(tactic["name"])  # add tactic header

            # parse techniques in tactic
            techniques = list(
                filter(
                    lambda t: not ("x_mitre_is_subtechnique" in t and t["x_mitre_is_subtechnique"]),
                    src.query(
                        [
                            Filter("type", "=", "attack-pattern"),
                            Filter(
                                "kill_chain_phases.phase_name",
                                "=",
                                tactic["x_mitre_shortname"],
                            ),
                        ]
                    ),
                )
            )
            techniques = remove_revoked_deprecated(techniques)
            techniques = sorted(techniques, key=lambda x: x["name"])
            # add techniques
            build_technique_and_sub_columns(
                src=src,
                techniques=techniques,
                columns=columns,
                merge_data_handle=merge,
                matrix_grid_handle=matrix_grid,
                tactic_name=tactic["name"]
            )

            for platform in MATRIX_PLATFORMS_LOOKUP[domain]:
                # In order to support "groups" of platforms, each platform is checked against the lookup a second time.
                # If an second entry can be found, the results from that query will be used, otherwise, the singular
                # platform will be.
                a_techs = filter_platforms(
                    techniques,
                    MATRIX_PLATFORMS_LOOKUP[platform] if platform in MATRIX_PLATFORMS_LOOKUP else [platform],
                )
                if a_techs:
                    sub_matrices_columns[platform].append(tactic["name"])
                    build_technique_and_sub_columns(
                        src=src,
                        techniques=a_techs,
                        columns=sub_matrices_columns[platform],
                        merge_data_handle=sub_matrices_merges[platform],
                        matrix_grid_handle=sub_matrices_grid[platform],
                        tactic_name=tactic["name"],
                        platform=platform
                    )

        # square the grid because pandas doesn't like jagged columns
        longest_column = 0
        for column in matrix_grid:
            longest_column = max(len(column), longest_column)
        for column in matrix_grid:
            for i in range((longest_column - len(column))):
                column.append("")

        for submatrix in sub_matrices_grid:
            mg = sub_matrices_grid[submatrix]
            for column in mg:
                longest_column = max(len(column), longest_column)
            for column in mg:
                for i in range((longest_column - len(column))):
                    column.append("")
        # matrix is now squared

        parsed = build_parsed_DF_matrix(matrix_grid, columns, merge, parsed)
        matrices_parsed.append(parsed)

        for submatrix in sub_matrices_grid:
            if sub_matrices_grid[submatrix]:  # make sure we found matches for something
                local = copy.deepcopy(parsed)
                local["name"] = f"{submatrix}" if len(matrices) == 1 else f"{submatrix} {matrix['name']}"
                local["description"] = local["description"].split(":")[0] + f": {submatrix}"
                subparsed = build_parsed_DF_matrix(
                    sub_matrices_grid[submatrix],
                    sub_matrices_columns[submatrix],
                    sub_matrices_merges[submatrix],
                    local,
                )
                sub_matrices_parsed.append(subparsed)

    # end adding of matrices
    return matrices_parsed, sub_matrices_parsed


def relationshipsToDf(src, relatedType=None):
    """Parse STIX relationships from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param relatedType: optional, singular attack type to only return relationships with, e.g "mitigation"
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    # Helper lookups
    attackToStixTerm = {
        "technique": ["attack-pattern"],
        "tactic": ["x-mitre-tactic"],
        "software": ["tool", "malware"],
        "group": ["intrusion-set"],
        "mitigation": ["course-of-action"],
        "matrix": ["x-mitre-matrix"],
        "datasource": ["x-mitre-data-component"],
    }
    stixToAttackTerm = {
        "attack-pattern": "technique",
        "x-mitre-tactic": "tactic",
        "tool": "software",
        "malware": "software",
        "intrusion-set": "group",
        "course-of-action": "mitigation",
        "x-mitre-matrix": "matrix",
        "x-mitre-data-component": "datacomponent",
        "x-mitre-data-source": "datasource",
    }

    # get master list of relationships
    relationships = src.query([Filter("type", "=", "relationship")])
    relationships = remove_revoked_deprecated(relationships)
    relationship_rows = []  # build list of rows for dataframe
    # tqdm description depends on the related type and parameters
    iterdesc = "parsing all relationships" if not relatedType else f"parsing relationships for type={relatedType}"
    for relationship in tqdm(relationships, desc=iterdesc):
        source = src.get(relationship["source_ref"])  # source object of the relationship
        target = src.get(relationship["target_ref"])  # target object of the relationship

        # filter if related objects don't exist or are revoked or deprecated
        if not source or source.get("x_mitre_deprecated", False) is True or source.get("revoked", False) is True:
            continue
        if not target or target.get("x_mitre_deprecated", False) is True or target.get("revoked", False) is True:
            continue
        if relationship["relationship_type"] == "revoked":
            continue

        # don't track sub-technique relationships, those are tracked in the techniques df
        if relationship["relationship_type"] == "subtechnique-of":
            continue

        # filter out relationships not with relatedType
        if relatedType:
            related = False
            for stixTerm in attackToStixTerm[relatedType]:  # try all stix types for the ATT&CK type
                if (
                    source["type"] == stixTerm or target["type"] == stixTerm
                ):  # if any stix type is part of the relationship
                    related = True
                    break
            if not related:
                continue  # skip this relationship if the types don't match

        # add mapping data
        row = {}

        def add_side(label, sdo):
            """Add data for one side of the mapping."""
            # logger.debug(sdo)
            if sdo.get("external_references"):
                if sdo["external_references"][0]["source_name"] in MITRE_ATTACK_ID_SOURCE_NAMES:
                    row[f"{label} ID"] = sdo["external_references"][0]["external_id"]  # "source ID" or "target ID"
            if "name" in sdo:
                row[f"{label} name"] = sdo["name"]  # "source name" or "target name"
            row[f"{label} type"] = stixToAttackTerm[sdo["type"]]  # "source type" or "target type"

        add_side("source", source)
        row["mapping type"] = relationship["relationship_type"]  # mapping type goes between the source/target data
        add_side("target", target)
        if "description" in relationship:  # add description of relationship to the end of the row
            row["mapping description"] = relationship["description"]

        relationship_rows.append(row)

    citations = get_citations(relationships)
    relationships = pd.DataFrame(relationship_rows).sort_values(
        ["mapping type", "source type", "target type", "source name", "target name"]
    )

    if not relatedType:  # return all relationships and citations
        dataframes = {
            "relationships": relationships,
        }
        if not citations.empty:
            dataframes["citations"] = citations.sort_values("reference")

        return dataframes
    else:  # break into dataframes by mapping type
        dataframes = {}

        # group:software / "associated {other type}"
        relatedGroupSoftware = relationships.query(
            "`mapping type` == 'uses' and (`source type` == 'group' or `source type` == 'software') and "
            "(`target type` == 'group' or `target type` == 'software')"
        )
        if not relatedGroupSoftware.empty:
            dataframes[f"associated {'software' if relatedType == 'group' else 'groups'}"] = relatedGroupSoftware

        # technique:group + technique:software / "procedure examples"
        procedureExamples = relationships.query("`mapping type` == 'uses' and `target type` == 'technique'")
        if not procedureExamples.empty:
            dataframes["procedure examples" if relatedType == "technique" else "techniques used"] = procedureExamples

        # technique:mitigation / "mitigation mappings"
        relatedMitigations = relationships.query("`mapping type` == 'mitigates'")
        if not relatedMitigations.empty:
            dataframes[
                "associated mitigations" if relatedType == "technique" else "techniques addressed"
            ] = relatedMitigations

        if not citations.empty:
            # filter citations by ones actually used
            # build master list of used citations
            usedCitations = set()
            for dfname in dataframes:
                df = dataframes[dfname]
                for description in filter(
                    lambda x: x == x, df["mapping description"].tolist()
                ):  # filter out missing descriptions which for whatever reason
                    # in pandas don't equal themselves
                    [usedCitations.add(x) for x in re.findall(r"\(Citation: (.*?)\)", description)]

            citations = citations[citations.reference.isin(list(usedCitations))]  # filter to only used references

            dataframes["citations"] = citations.sort_values("reference")

        return dataframes


def _get_relationship_citations(object_dataframe, relationship_df):
    """Extract citations for each _object_ in the relationship dataframe.

    This allows us to include citations from relationships for each ATT&CK object type.

    :param object_dataframe: Dataframe for relevant ATT&CK object
    :param relationship_df: Dataframe of relationships
    :return: Array of strings, with each string being placed relative to the object listing, and containing all
        relevant citations
    """
    object_listing = [x for x in object_dataframe["ID"]]
    new_citations = []
    for z in [x for x in relationship_df if x != "citations"]:
        subset = []
        for y in object_listing:
            mask = relationship_df[z].values == y
            filtered = relationship_df[z].loc[mask]
            temp = set()
            for description in filter(lambda x: x == x, filtered["mapping description"].tolist()):
                [temp.add(x) for x in re.findall(r"\(Citation: (.*?)\)", description)]
            subset.append(",".join([f"(Citation: {z})" for z in temp]))
        if not new_citations:
            new_citations = subset
        else:
            for i in range(0, len(new_citations)):
                new_citations[i] = ",".join([new_citations[i], subset[i]])
    return new_citations
