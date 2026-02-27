"""Helper functions to convert STIX to pandas dataframes."""

import copy
import datetime
import re
from itertools import chain

import numpy as np
import pandas as pd
from loguru import logger
from stix2 import Filter, MemoryStore
from tqdm import tqdm

from mitreattack.constants import MITRE_ATTACK_ID_SOURCE_NAMES, PLATFORMS_LOOKUP

# Module-level constants for type mappings (avoid recreating per call)
_ATTACK_TO_STIX_TERM = {
    "technique": ["attack-pattern"],
    "tactic": ["x-mitre-tactic"],
    "software": ["tool", "malware"],
    "group": ["intrusion-set"],
    "campaign": ["campaign"],
    "asset": ["x-mitre-asset"],
    "mitigation": ["course-of-action"],
    "matrix": ["x-mitre-matrix"],
    "datasource": ["x-mitre-data-component"],
    "detectionstrategy": ["x-mitre-detection-strategy"],
}

_STIX_TO_ATTACK_TERM = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "tool": "software",
    "malware": "software",
    "intrusion-set": "group",
    "course-of-action": "mitigation",
    "x-mitre-matrix": "matrix",
    "x-mitre-data-component": "datacomponent",
    "x-mitre-data-source": "datasource",
    "campaign": "campaign",
    "x-mitre-asset": "asset",
    "x-mitre-detection-strategy": "detectionstrategy",
}


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
    return f"{date.strftime('%d')} {date.strftime('%B')} {date.strftime('%Y')}"


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
    if "id" in sdo:  # required for workbench collection import
        row["STIX ID"] = sdo["id"]
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
    if "x_mitre_domains" in sdo:  # required for workbench collection import
        row["domain"] = ",".join(sdo["x_mitre_domains"])
    if "x_mitre_version" in sdo:
        row["version"] = sdo["x_mitre_version"]
    if "x_mitre_contributors" in sdo:
        row["contributors"] = "; ".join(sorted(sdo["x_mitre_contributors"]))
    return row


def _extract_attack_id(obj):
    """Extract ATT&CK ID from an already-fetched STIX object without re-fetching."""
    external_references = obj.get("external_references", [])
    if external_references:
        attack_source = external_references[0]
        if attack_source.get("external_id") and attack_source.get("source_name") == "mitre-attack":
            return attack_source["external_id"]
    return None


def _prefetch_data_components(src, analytics):
    """Pre-fetch all data components referenced by analytics into a dict for O(1) lookups.

    :param src: MemoryStore or other stix2 DataSource object
    :param analytics: list of analytic STIX objects
    :returns: dict of data_component_id -> data_component_object
    """
    all_dc_ids = set()
    for analytic in analytics:
        for logsrc in analytic.get("x_mitre_log_source_references", []):
            dc_id = logsrc.get("x_mitre_data_component_ref", "")
            if dc_id:
                all_dc_ids.add(dc_id)
    dc_cache = {}
    for dc_id in all_dc_ids:
        dc_obj = src.get(dc_id)
        if dc_obj is not None:
            dc_cache[dc_id] = dc_obj
    return dc_cache


def _process_all_relationships(src):
    """Process all relationships from the STIX data source into a sorted DataFrame and citations.

    This is the expensive operation (object lookups, iteration) that should only be done once
    per export. The result can be passed to relationshipsToDf() via the _precomputed parameter
    to avoid redundant processing.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :returns: tuple of (sorted_relationship_df, citations_df)
    """
    relationships_stix = src.query([Filter("type", "=", "relationship")])
    relationships_stix = remove_revoked_deprecated(relationships_stix)

    # Pre-fetch all referenced objects to avoid N+1 lookup pattern.
    # Instead of calling src.get() 2-4 times per relationship in the loop,
    # we collect all unique IDs and fetch each object exactly once.
    referenced_ids = set()
    for rel in relationships_stix:
        referenced_ids.add(rel["source_ref"])
        referenced_ids.add(rel["target_ref"])

    object_cache = {}
    for obj_id in referenced_ids:
        obj = src.get(obj_id)
        if obj is not None:
            object_cache[obj_id] = obj

    relationship_rows = []
    for relationship in tqdm(relationships_stix, desc="parsing all relationships"):
        source = object_cache.get(relationship["source_ref"])
        target = object_cache.get(relationship["target_ref"])

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

        row = {}
        # Extract ATT&CK IDs directly from already-fetched objects
        # (avoids the redundant src.get() that MitreAttackData.get_attack_id() would do)
        row["source ID"] = _extract_attack_id(source)
        row["source name"] = source.get("name")
        row["source ref"] = source.get("id")
        row["source type"] = _STIX_TO_ATTACK_TERM.get(source["type"])

        row["mapping type"] = relationship["relationship_type"]

        row["target ID"] = _extract_attack_id(target)
        row["target name"] = target.get("name")
        row["target ref"] = target.get("id")
        row["target type"] = _STIX_TO_ATTACK_TERM.get(target["type"])

        if "description" in relationship:
            row["mapping description"] = relationship["description"]
        row["STIX ID"] = relationship["id"]
        if "created" in relationship:
            row["created"] = format_date(relationship["created"])
        if "modified" in relationship:
            row["last modified"] = format_date(relationship["modified"])
        relationship_rows.append(row)

    citations = get_citations(relationships_stix)

    relationship_df = pd.DataFrame(relationship_rows)
    if relationship_df.empty or "mapping type" not in relationship_df.columns:
        return (pd.DataFrame(), citations)

    relationship_df = relationship_df.sort_values(
        [
            "mapping type",
            "source type",
            "target type",
            "source name",
            "target name",
            "source ref",
            "target ref",
            "created",
            "last modified",
        ]
    )

    return (relationship_df, citations)


def techniquesToDf(src, domain, *, _rel_data=None):
    """Parse STIX techniques from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK src corresponds to, e.g "enterprise-attack"
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    techniques = src.query([Filter("type", "=", "attack-pattern")])
    techniques = remove_revoked_deprecated(techniques)
    technique_rows = []

    tactics = src.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = remove_revoked_deprecated(tactics)
    tactic_names = {}
    for tactic in tactics:
        x_mitre_shortname = tactic["x_mitre_shortname"]
        tactic_names[x_mitre_shortname] = tactic["name"]
    missing_tactic_shortnames = set()

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
        else:
            parent = None

        # base STIX properties
        row = parseBaseStix(technique)

        # sub-technique properties
        if "kill_chain_phases" not in technique:
            attack_id = technique["external_references"][0]["external_id"]
            logger.error(f"Skipping {attack_id} [{technique['id']}] because it does't have kill chain phases")
            continue
        tactic_shortnames = []
        for kcp in technique["kill_chain_phases"]:
            tactic_shortnames.append(kcp["phase_name"])

        technique_tactic_names = []
        for shortname in tactic_shortnames:
            tactic_display_name = tactic_names.get(shortname)
            if not tactic_display_name:
                tactic_display_name = shortname.replace("-", " ").title()
                if shortname not in missing_tactic_shortnames:
                    logger.warning(
                        f"Could not find x-mitre-tactic object for shortname '{shortname}', using '{tactic_display_name}'"
                    )
                    missing_tactic_shortnames.add(shortname)
            technique_tactic_names.append(tactic_display_name)
        row["tactics"] = ", ".join(sorted(technique_tactic_names))

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
            if subtechnique and parent is not None:
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
    rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
    codex = relationshipsToDf(src, relatedType="technique", **rel_kwargs)
    dataframes.update(codex)
    # add relationship references
    dataframes["techniques"]["relationship citations"] = _get_relationship_citations(dataframes["techniques"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def tacticsToDf(src):
    """Parse STIX tactics from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    tactics = src.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = remove_revoked_deprecated(tactics)

    tactic_rows = []
    for tactic in tqdm(tactics, desc="parsing tactics"):
        tactic_rows.append(parseBaseStix(tactic))

    citations = get_citations(tactics)
    dataframes = {
        "tactics": pd.DataFrame(tactic_rows).sort_values("name"),
    }
    if not citations.empty:
        dataframes["citations"] = citations.sort_values("reference")

    return dataframes


def datasourcesToDf(src, *, _rel_data=None):
    """Parse STIX Data Sources and their Data components from the given data and return corresponding pandas dataframes.

    This is only used in versions of ATT&CK before v18.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    data = list(
        chain.from_iterable(  # collect all data components and data sources
            src.query(f)
            for f in [
                Filter("type", "=", "x-mitre-data-component"),
                Filter("type", "=", "x-mitre-data-source"),
            ]
        )
    )
    dataframes = {}
    if data:
        refined = remove_revoked_deprecated(data)
        data_object_rows = []
        source_lookup = dict()
        for x in refined:
            if x["type"] == "x-mitre-data-source":
                source_lookup[x["id"]] = x["name"]
        for data_object in tqdm(refined, desc="parsing data sources"):
            # add common STIX fields
            row = parseBaseStix(data_object)
            # add data source/data component-specific fields
            if "x_mitre_platforms" in data_object:
                row["platforms"] = ", ".join(sorted(data_object["x_mitre_platforms"]))
            if "x_mitre_collection_layers" in data_object:
                row["collection layers"] = ", ".join(sorted(data_object["x_mitre_collection_layers"]))
            if "x_mitre_aliases" in data_object:
                row["aliases"] = ", ".join(sorted(data_object["x_mitre_aliases"][1:]))
            if data_object["type"] == "x-mitre-data-component":
                if "x_mitre_data_source_ref" in data_object and data_object["x_mitre_data_source_ref"] in source_lookup:
                    row["name"] = f"{source_lookup[data_object['x_mitre_data_source_ref']]}: {data_object['name']}"
                row["type"] = "datacomponent"
            else:
                row["type"] = "datasource"
            if "description" in data_object:
                row["description"] = data_object["description"]
            data_object_rows.append(row)

        citations = get_citations(refined)
        tempa = pd.DataFrame(data_object_rows).sort_values("name")
        dataframes["datasources"] = tempa.reindex(
            columns=[
                "name",
                "ID",
                "STIX ID",
                "description",
                "collection layers",
                "platforms",
                "created",
                "last modified",
                "type",
                "version",
                "url",
                "contributors",
            ]
        )
        # add relationships
        rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
        dataframes.update(relationshipsToDf(src, relatedType="datasource", **rel_kwargs))
        # add/merge citations
        if not citations.empty:
            if "citations" in dataframes:  # append to existing citations from references
                dataframes["citations"] = pd.concat([dataframes["citations"], citations])
            else:  # add citations
                dataframes["citations"] = citations

            dataframes["citations"].sort_values("reference")
    else:
        logger.warning("No data components or data sources found - nothing to parse")

    return dataframes


def datacomponentsToDf(src):
    """Parse STIX Data components from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    data_components = src.query([Filter("type", "=", "x-mitre-data-component")])
    data_components = remove_revoked_deprecated(data_components)

    data_component_rows = []
    for data_component in tqdm(data_components, desc="parsing data components"):
        data_component_rows.append(parseBaseStix(data_component))

    citations = get_citations(data_components)
    dataframes = {
        "datacomponents": pd.DataFrame(data_component_rows).sort_values("name"),
    }
    if not citations.empty:
        dataframes["citations"] = citations.sort_values("reference")

    return dataframes


def analyticsToDf(src):
    """Parse STIX Analytics from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    analytics = src.query([Filter("type", "=", "x-mitre-analytic")])
    analytics = remove_revoked_deprecated(analytics)

    # Detection strategies (needed for analytics to detection strategies relationship)
    detection_strategies = src.query([Filter("type", "=", "x-mitre-detection-strategy")])
    detection_strategies = remove_revoked_deprecated(detection_strategies)

    dataframes = {}
    if analytics:
        analytic_rows = []
        logsource_rows = []
        analytic_to_ds_rows = []
        failed_by_data_component = {}

        # analytics to detection strategies
        analytic_to_ds_map = {}
        for ds in detection_strategies:
            for analytic_id in ds.get("x_mitre_analytic_refs", []):
                analytic_to_ds_map.setdefault(analytic_id, []).append(
                    {
                        "detection_strategy_attack_id": ds["external_references"][0]["external_id"],
                        "detection_strategy_id": ds["id"],
                        "detection_strategy_name": ds.get("name", ""),
                    }
                )

        dc_cache = _prefetch_data_components(src, analytics)

        # Single pass: validate and build rows together
        for analytic in tqdm(analytics, desc="parsing analytics"):
            analytic_id = analytic.get("id")
            analytic_rows.append(parseBaseStix(analytic))

            # log-source relationship table rows (also validates data components)
            for logsrc in analytic.get("x_mitre_log_source_references", []):
                data_comp_id = logsrc.get("x_mitre_data_component_ref", "")
                data_comp = dc_cache.get(data_comp_id)
                try:
                    data_comp_attack_id = data_comp["external_references"][0]["external_id"]
                except (KeyError, TypeError, IndexError, AttributeError):
                    if data_comp_id not in failed_by_data_component:
                        failed_by_data_component[data_comp_id] = []
                    failed_by_data_component[data_comp_id].append(analytic_id)
                    continue

                data_comp_name = data_comp.get("name", "") if data_comp else ""

                logsource_rows.append(
                    {
                        "analytic_id": analytic["id"],
                        "analytic_name": analytic["external_references"][0]["external_id"],
                        "data_component_id": data_comp_id,
                        "data_component_name": data_comp_name,
                        "data_component_attack_id": data_comp_attack_id,
                        "log_source_name": logsrc.get("name", ""),
                        "channel": logsrc.get("channel", ""),
                        "platforms": ", ".join(sorted(analytic.get("x_mitre_platforms", []))),
                    }
                )

            # detection strategies relationship table rows
            for ds_info in analytic_to_ds_map.get(analytic["id"], []):
                analytic_to_ds_rows.append(
                    {
                        "analytic_id": analytic["id"],
                        "analytic_name": analytic["external_references"][0]["external_id"],
                        "detection_strategy_id": ds_info["detection_strategy_id"],
                        "detection_strategy_attack_id": ds_info["detection_strategy_attack_id"],
                        "detection_strategy_name": ds_info["detection_strategy_name"],
                        "platforms": ", ".join(sorted(analytic.get("x_mitre_platforms", []))),
                    }
                )

        if failed_by_data_component:
            lines = ["Failures grouped by data component:\n"]
            for dc_id in sorted(failed_by_data_component):
                analytic_ids = sorted(set(failed_by_data_component[dc_id]))
                dc_obj = dc_cache.get(dc_id, {})
                dc_name = dc_obj.get("name", "")

                lines.append(f"data_component={dc_id}" + (f" ({dc_name})" if dc_name else ""))
                lines.extend([f"  - analytic={a}" for a in analytic_ids])
                lines.append("")

            raise RuntimeError("\n".join(lines))

        dataframes["analytics"] = pd.DataFrame(analytic_rows).sort_values("name")

        citations = get_citations(analytics)
        if not citations.empty:
            dataframes["citations"] = citations.sort_values("reference")

    else:
        logger.warning("No analytics found - nothing to parse")

    return dataframes


def detectionstrategiesToDf(src):
    """Parse STIX Detection Strategies from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    detection_strategies = src.query([Filter("type", "=", "x-mitre-detection-strategy")])
    detection_strategies = remove_revoked_deprecated(detection_strategies)

    dataframes = {}
    if detection_strategies:
        detection_strategy_rows = []
        rel_rows = []

        # Pre-fetch all referenced analytics once instead of per-detection-strategy
        all_analytic_ids = set()
        for ds in detection_strategies:
            for a_id in ds.get("x_mitre_analytic_refs", []):
                all_analytic_ids.add(a_id)
        analytic_cache = {}
        for a_id in all_analytic_ids:
            a_obj = src.get(a_id)
            if a_obj is not None:
                analytic_cache[a_id] = a_obj

        for detection_strategy in tqdm(detection_strategies, desc="parsing detection strategies"):
            row = parseBaseStix(detection_strategy)
            row["analytic_refs"] = "; ".join(detection_strategy.get("x_mitre_analytic_refs", []))
            detection_strategy_rows.append(row)

            # analytics relationship table rows
            for analytic_id in detection_strategy.get("x_mitre_analytic_refs", []):
                analytic_obj = analytic_cache.get(analytic_id)

                rel_rows.append(
                    {
                        "detection_strategy_attack_id": detection_strategy["external_references"][0]["external_id"],
                        "detection_strategy_id": detection_strategy["id"],
                        "detection_strategy_name": detection_strategy.get("name", ""),
                        "analytic_id": analytic_id,
                        "analytic_name": analytic_obj["external_references"][0]["external_id"],
                        "platforms": ", ".join(sorted(analytic_obj.get("x_mitre_platforms", []))),
                    }
                )

        # Build main dataframes
        dataframes["detectionstrategies"] = pd.DataFrame(detection_strategy_rows).sort_values("name")

        citations = get_citations(detection_strategies)
        if not citations.empty:
            dataframes["citations"] = citations.sort_values("reference")

    else:
        logger.warning("No detection strategies found - nothing to parse")
    return dataframes


def softwareToDf(src, *, _rel_data=None):
    """Parse STIX software from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
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
    rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
    codex = relationshipsToDf(src, relatedType="software", **rel_kwargs)
    dataframes.update(codex)
    # add relationship references
    dataframes["software"]["relationship citations"] = _get_relationship_citations(dataframes["software"], codex)
    # add/merge citations
    if not citations.empty:
        if "citations" in dataframes:  # append to existing citations from references
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def detectionStrategiesAnalyticsLogSourcesDf(src):
    """Build a single DS -> LogSource -> Analytic dataframe directly from STIX."""
    detection_strategies = src.query([Filter("type", "=", "x-mitre-detection-strategy")])
    detection_strategies = remove_revoked_deprecated(detection_strategies)

    analytics = src.query([Filter("type", "=", "x-mitre-analytic")])
    analytics = remove_revoked_deprecated(analytics)
    analytics_by_id = {a["id"]: a for a in analytics}

    dc_cache = _prefetch_data_components(src, analytics)

    rows = []
    for ds in detection_strategies:
        ds_attack_id = ds.get("external_references", [{}])[0].get("external_id", "")
        ds_id = ds.get("id", "")
        ds_name = ds.get("name", "")

        for analytic_id in ds.get("x_mitre_analytic_refs", []):
            analytic = analytics_by_id.get(analytic_id)
            analytic_attack_id = analytic["external_references"][0]["external_id"]
            platforms = ", ".join(sorted(analytic.get("x_mitre_platforms", [])))

            logsrc_refs = analytic.get("x_mitre_log_source_references", [])
            for logsrc in logsrc_refs:
                data_comp_id = logsrc.get("x_mitre_data_component_ref", "")
                data_comp = dc_cache.get(data_comp_id)

                rows.append(
                    {
                        "detection_strategy_attack_id": ds_attack_id,
                        "detection_strategy_id": ds_id,
                        "detection_strategy_name": ds_name,
                        "analytic_id": analytic_id,
                        "analytic_name": analytic_attack_id,
                        "platforms": platforms,
                        "log_source_name": logsrc.get("name", ""),
                        "channel": logsrc.get("channel", ""),
                        "data_component_id": data_comp_id,
                        "data_component_name": (data_comp.get("name", "") if data_comp else ""),
                        "data_component_attack_id": data_comp["external_references"][0]["external_id"],
                    }
                )

    return pd.DataFrame(rows)


def groupsToDf(src, *, _rel_data=None):
    """Parse STIX groups from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
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
    rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
    codex = relationshipsToDf(src, relatedType="group", **rel_kwargs)
    dataframes.update(codex)
    # add relationship references
    dataframes["groups"]["relationship citations"] = _get_relationship_citations(dataframes["groups"], codex)
    # add/merge citations
    if not citations.empty:
        # append to existing citations from references
        if "citations" in dataframes:
            dataframes["citations"] = pd.concat([dataframes["citations"], citations])
        else:  # add citations
            dataframes["citations"] = citations

        dataframes["citations"].sort_values("reference")

    return dataframes


def campaignsToDf(src, *, _rel_data=None):
    """Parse STIX campaigns from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    campaigns = src.query([Filter("type", "=", "campaign")])
    campaigns = remove_revoked_deprecated(campaigns)

    dataframes = {}
    if campaigns:
        campaign_rows = []
        for campaign in tqdm(campaigns, desc="parsing campaigns"):
            row = parseBaseStix(campaign)

            # add group aliases
            if "aliases" in campaign:
                associated_campaigns = []
                associated_campaign_citations = []
                for alias in sorted(campaign["aliases"][1:]):
                    # find the reference for the alias
                    associated_campaigns.append(alias)
                    for ref in campaign["external_references"]:
                        if ref["source_name"] == alias:
                            associated_campaign_citations.append(ref["description"])
                            break
                            # aliases.append(alias)
                row["associated campaigns"] = ", ".join(associated_campaigns)
                row["associated campaigns citations"] = ", ".join(associated_campaign_citations)
            # add fields required to import excel to workbench:
            row["first seen"] = format_date(campaign["first_seen"])
            row["first seen citation"] = campaign["x_mitre_first_seen_citation"]
            row["last seen"] = format_date(campaign["last_seen"])
            row["last seen citation"] = campaign["x_mitre_last_seen_citation"]

            campaign_rows.append(row)

        citations = get_citations(campaigns)
        dataframes = {
            "campaigns": pd.DataFrame(campaign_rows).sort_values("name"),
        }
        # add relationships
        rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
        codex = relationshipsToDf(src, relatedType="campaign", **rel_kwargs)
        dataframes.update(codex)

        # add relationship references
        dataframes["campaigns"]["relationship citations"] = _get_relationship_citations(dataframes["campaigns"], codex)

        # add/merge citations
        if not citations.empty:
            # append to existing citations from references
            if "citations" in dataframes:
                dataframes["citations"] = pd.concat([dataframes["citations"], citations])
            else:
                dataframes["citations"] = citations

            dataframes["citations"].sort_values("reference")
    else:
        logger.warning("No campaigns found - nothing to parse")

    return dataframes


def assetsToDf(src, *, _rel_data=None):
    """Parse STIX assets from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    assets = src.query([Filter("type", "=", "x-mitre-asset")])
    assets = remove_revoked_deprecated(assets)

    dataframes = {}
    if assets:
        asset_rows = []
        for asset in tqdm(assets, desc="parsing assets"):
            row = parseBaseStix(asset)
            # add asset-specific fields
            if "x_mitre_platforms" in asset:
                row["platforms"] = ", ".join(sorted(asset["x_mitre_platforms"]))
            if "x_mitre_sectors" in asset:
                row["sectors"] = ", ".join(sorted(asset["x_mitre_sectors"]))
            if "x_mitre_related_assets" in asset:
                related_assets = []
                related_assets_sectors = []
                related_assets_descriptions = []

                for related_asset in asset["x_mitre_related_assets"]:
                    related_assets.append(related_asset["name"])
                    related_assets_sectors.append(", ".join(related_asset["related_asset_sectors"]))
                    related_assets_descriptions.append(related_asset["description"])

                row["related assets"] = "; ".join(related_assets)
                row["related assets sectors"] = "; ".join(related_assets_sectors)
                row["related assets description"] = "; ".join(related_assets_descriptions)

            asset_rows.append(row)

        citations = get_citations(assets)
        dataframes = {
            "assets": pd.DataFrame(asset_rows).sort_values("name"),
        }
        # add relationships
        rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
        codex = relationshipsToDf(src, relatedType="asset", **rel_kwargs)
        dataframes.update(codex)
        # add relationship references
        dataframes["assets"]["relationship citations"] = _get_relationship_citations(dataframes["assets"], codex)
        # add/merge citations
        if not citations.empty:
            # append to existing citations from references
            if "citations" in dataframes:
                dataframes["citations"] = pd.concat([dataframes["citations"], citations])
            else:  # add citations
                dataframes["citations"] = citations

            dataframes["citations"].sort_values("reference")
    else:
        logger.warning("No assets found - nothing to parse")

    return dataframes


def mitigationsToDf(src, *, _rel_data=None):
    """Parse STIX mitigations from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param _rel_data: optional pre-computed relationship data from _process_all_relationships()
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
    rel_kwargs = {"_precomputed": _rel_data} if _rel_data is not None else {}
    codex = relationshipsToDf(src, relatedType="mitigation", **rel_kwargs)
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


def build_technique_and_sub_columns(
    src,
    techniques,
    columns,
    merge_data_handle,
    matrix_grid_handle,
    tactic_name,
    platform=None,
    *,
    _sub_techniques_store=None,
):
    """Build technique and subtechnique columns for a given matrix and attach them to the appropriate object listings.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param techniques: List of technique stix objects belong in this tactic column
    :param columns: Existing columns in this matrix (used for placement)
    :param merge_data_handle: Handle to the 'merge' data object for this matrix
    :param matrix_grid_handle: Handle to the 2D grid array being constructed for the matrix (technique and subtechnique
                                columns will be appended here)
    :param tactic_name: The name of the corresponding tactic for this column
    :param platform: [Optional] The name of a platform to filter subtechniques by
    :param _sub_techniques_store: [Optional] Pre-computed MemoryStore of subtechnique-of relationships

    :return: Nothing (meta - modifies the passed in merge_data_handle and matrix_grid_handle objects)
    """
    techniques_column = []
    subtechniques_column = []

    if _sub_techniques_store is not None:
        all_sub_techniques = _sub_techniques_store
    else:
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

        # if there are sub-techniques on the tactic
        if len(subtechnique_ofs) > 0:
            # top of row range to merge
            technique_top = len(techniques_column) + 1

            subtechniques = [src.get(rel["source_ref"]) for rel in subtechnique_ofs]
            if platform:
                subtechniques = filter_platforms(
                    subtechniques,
                    PLATFORMS_LOOKUP[platform] if platform in PLATFORMS_LOOKUP else [platform],
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

        # no sub-techniques; add empty cell parallel to technique
        else:
            subtechniques_column.append("")
    # end adding techniques and sub-techniques to column

    # add technique column to grid
    matrix_grid_handle.append(techniques_column)

    # if there are sub-techniques for the tactic
    if len(list(filter(lambda x: x != "", subtechniques_column))) > 0:
        # add sub-technique sub-column
        matrix_grid_handle.append(subtechniques_column)

        # add empty tactic header for the sub-column
        columns.append("")

        # merge tactic column header with the sub-column header that was just appended
        merge_data_handle.append(
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
    """Parse STIX matrices from the given data and return parsed matrix structures.

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

    # Pre-compute subtechnique-of relationships once instead of per-tactic/per-platform
    all_sub_technique_rels = src.query(
        [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "subtechnique-of"),
        ]
    )
    sub_techniques_store = MemoryStore(stix_data=all_sub_technique_rels)

    for matrix in tqdm(matrices, desc="parsing matrices"):
        sub_matrices_grid = dict()
        sub_matrices_merges = dict()
        sub_matrices_columns = dict()
        for entry in PLATFORMS_LOOKUP[domain]:
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
                tactic_name=tactic["name"],
                _sub_techniques_store=sub_techniques_store,
            )

            for platform in PLATFORMS_LOOKUP[domain]:
                # In order to support "groups" of platforms, each platform is checked against the lookup a second time.
                # If an second entry can be found, the results from that query will be used, otherwise, the singular
                # platform will be.
                a_techs = filter_platforms(
                    techniques,
                    PLATFORMS_LOOKUP[platform] if platform in PLATFORMS_LOOKUP else [platform],
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
                        platform=platform,
                        _sub_techniques_store=sub_techniques_store,
                    )

        # square the grid because pandas doesn't like jagged columns
        longest_column = 0
        for column in matrix_grid:
            longest_column = max(len(column), longest_column)
        for column in matrix_grid:
            for _ in range((longest_column - len(column))):
                column.append("")

        for submatrix in sub_matrices_grid:
            mg = sub_matrices_grid[submatrix]
            for column in mg:
                longest_column = max(len(column), longest_column)
            for column in mg:
                for _ in range((longest_column - len(column))):
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


def relationshipsToDf(src, relatedType=None, *, _precomputed=None):
    """Parse STIX relationships from the given data and return corresponding pandas dataframes.

    :param src: MemoryStore or other stix2 DataSource object holding the domain data
    :param relatedType: optional, singular attack type to only return relationships with, e.g "mitigation"
    :param _precomputed: optional, pre-computed (relationship_df, citations) tuple from _process_all_relationships().
        When provided, skips the expensive relationship processing and only performs filtering/categorization.
    :returns: a lookup of labels (descriptors/names) to dataframes
    """
    if _precomputed is not None:
        relationships, citations = _precomputed
    else:
        relationships, citations = _process_all_relationships(src)

    if relationships.empty or "mapping type" not in relationships.columns:
        logger.warning(f"No relationships found for relatedType={relatedType}. Returning empty dataframe.")
        return {}

    # Filter to only relationships involving the requested type
    if relatedType:
        # Map relatedType to the ATT&CK type names used in the DataFrame
        df_types = {_STIX_TO_ATTACK_TERM[t] for t in _ATTACK_TO_STIX_TERM[relatedType]}
        type_mask = relationships["source type"].isin(df_types) | relationships["target type"].isin(df_types)
        relationships = relationships[type_mask]
        if relationships.empty:
            logger.warning(f"No relationships found for relatedType={relatedType}. Returning empty dataframe.")
            return {}

    # return all relationships and citations
    if not relatedType:
        dataframes = {
            "relationships": relationships,
        }
        if not citations.empty:
            dataframes["citations"] = citations.sort_values("reference")

        return dataframes

    # break into dataframes by mapping type
    else:
        dataframes = {}

        relatedGroupSoftware = relationships.query(
            "(`source type` == 'group' or `source type` == 'software') and "
            "`mapping type` == 'uses' and "
            "(`target type` == 'group' or `target type` == 'software')"
        )
        relatedCampaignSoftware = relationships.query(
            "(`source type` == 'campaign' or `source type` == 'software') and "
            "`mapping type` == 'uses' and "
            "(`target type` == 'campaign' or `target type` == 'software')"
        )
        procedureExamples = relationships.query("`mapping type` == 'uses' and `target type` == 'technique'")
        attributedCampaignGroup = relationships.query("`mapping type` == 'attributed-to' and `target type` == 'group'")
        relatedMitigations = relationships.query("`mapping type` == 'mitigates'")
        targetedAssets = relationships.query("`mapping type` == 'targets' and `target type` == 'asset'")
        detectedTechniques = relationships.query("`mapping type` == 'detects' and `source type` == 'detectionstrategy'")

        if not relatedGroupSoftware.empty:
            if relatedType == "group":
                sheet_name = "associated software"
            else:
                sheet_name = "associated groups"
            dataframes[sheet_name] = relatedGroupSoftware

        if not relatedCampaignSoftware.empty:
            if relatedType == "campaign":
                sheet_name = "associated software"
            else:
                sheet_name = "associated campaigns"
            dataframes[sheet_name] = relatedCampaignSoftware

        if not procedureExamples.empty:
            if relatedType == "technique":
                sheet_name = "procedure examples"
            else:
                sheet_name = "techniques used"
            dataframes[sheet_name] = procedureExamples

        if not attributedCampaignGroup.empty:
            if relatedType == "campaign":
                sheet_name = "attributed groups"
            elif relatedType == "group":
                sheet_name = "attributed campaigns"
            else:
                sheet_name = "associated campaigns"
            dataframes[sheet_name] = attributedCampaignGroup

        if not relatedMitigations.empty:
            if relatedType == "technique":
                sheet_name = "associated mitigations"
            else:
                sheet_name = "techniques addressed"
            dataframes[sheet_name] = relatedMitigations

        if not targetedAssets.empty:
            if relatedType == "technique":
                sheet_name = "targeted assets"
            else:
                sheet_name = "associated techniques"
            dataframes[sheet_name] = targetedAssets

        if not detectedTechniques.empty:
            if relatedType == "detectionstrategy":
                sheet_name = "techniques detected"
            else:
                sheet_name = "associated detection strategies"
            dataframes[sheet_name] = detectedTechniques

        if not citations.empty:
            # filter citations by ones actually used
            # build master list of used citations
            usedCitations = set()
            for dfname in dataframes:
                df = dataframes[dfname]
                # filter out missing descriptions which for whatever reason
                for description in filter(lambda x: x == x, df["mapping description"].tolist()):
                    # in pandas don't equal themselves
                    [usedCitations.add(x) for x in re.findall(r"\(Citation: (.*?)\)", description)]

            # filter to only used references
            citations = citations[citations.reference.isin(list(usedCitations))]

            dataframes["citations"] = citations.sort_values("reference")

        return dataframes


def _get_relationship_citations(object_dataframe, relationship_df):
    """Extract citations for each _object_ in the relationship dataframe.

    This allows us to include citations from relationships for each ATT&CK object type.

    :param object_dataframe: Dataframe for relevant ATT&CK object
    :param relationship_df: dict of sheet_name -> DataFrame from relationshipsToDf()
    :return: Array of strings, with each string being placed relative to the object listing, and containing all
        relevant citations
    """
    all_ids = object_dataframe["ID"].tolist()
    id_set = set(all_ids)

    # Collect citations per object ID using efficient column-based filtering
    id_to_citations = {}

    for sheet_name, sheet_df in relationship_df.items():
        if sheet_name == "citations" or sheet_df.empty:
            continue
        if "mapping description" not in sheet_df.columns:
            continue

        for id_col in ["source ID", "target ID"]:
            if id_col not in sheet_df.columns:
                continue
            # Use .isin() for batch filtering (single pass) instead of per-ID comparison
            mask = sheet_df[id_col].isin(id_set)
            matching = sheet_df.loc[mask, [id_col, "mapping description"]].dropna(subset=["mapping description"])
            for obj_id, desc in zip(matching[id_col], matching["mapping description"], strict=True):
                for cite in re.findall(r"\(Citation: (.*?)\)", desc):
                    id_to_citations.setdefault(obj_id, set()).add(cite)

    return [",".join(f"(Citation: {c})" for c in id_to_citations.get(obj_id, set())) for obj_id in all_ids]
