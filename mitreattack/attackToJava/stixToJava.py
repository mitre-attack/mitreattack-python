from mitreattack.attackToExcel import stixToDf
from stix2 import Filter, MemoryStore


from pprint import pprint
from loguru import logger
from sortedcontainers import SortedDict
from sortedcontainers import SortedSet
from sortedcontainers import SortedList

import os
import sys
import jinja2
import shutil

script_dir = os.path.dirname(os.path.realpath(__file__))
template_dir = os.path.join(script_dir, "templates")


def runMaven(output_dir: str):
    """Run Maven to build the Java classes

    Parameters
    ----------
    output_dir : str required
        The directory to run Maven in
    """
    logger.info("Running Maven")
    os.system(f"mvn -f {output_dir} clean compile package")

#Function to remove tautology from the text, that is remove parts of the beginning of the text that are repeated
#that is WINDOWS_REGISTRY_WINDOWS_REGISTRY_KEY_CREATION should be reduced to WINDOWS_REGISTRY_KEY_CREATION
def remove_tautology(text: str):
    text_parts = text.split("_")
    if len(text_parts) < 2:
        return text

    #Find the first part that is repeated, going each part alone
    for i in range(1, len(text_parts)):
        if text_parts[i] == text_parts[i-1]:
            return "_".join(text_parts[i:])
        
    #Repeat same by combining two parts
    if len(text_parts) > 4:
        #Combine two parts and check if they are repeated
        for i in range(2, len(text_parts)):
            if text_parts[i] == text_parts[i-2] and text_parts[i-1] == text_parts[i-3]:
                return "_".join(text_parts[i-1:])

    return text

def formatTextToLines(text: str, max_line_length: int = 80):
    """Format text to lines of max_line_length

    Parameters
    ----------
    text : str
        The text to format

    max_line_length : int, optional
        The maximum line length, by default 80

    Returns
    -------
    list
        The formatted lines
    """

    lines = []
    for line in text.split("\n"):
        while len(line) > max_line_length:
            #Find the last space before 80 characters
            last_space = line.rfind(" ", 0, max_line_length)
            if last_space == -1:
                last_space = max_line_length
            lines.append(line[:last_space])
            line = line[last_space+1:]
        lines.append(line)
    return "\n".join(lines)


def buildOutputDir(package_name: str = None, output_dir: str = None):
    """
    Build the output directory for the Java classes

    Parameters
    ----------
    package_name : str
        The name of the package to create the directory for

    Returns
    -------
    str
        The path to the output directory
    """


    package_root_dir = os.path.join(output_dir,"src","main","java", package_name.replace(".", os.sep) )

    #Remove the output directory if it exists and is other than current dir
    if output_dir != "." and os.path.exists(output_dir):
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)

    os.makedirs(package_root_dir, exist_ok=True)

def nameToClassName(name: str):
    """Convert a name to a class name

    Parameters
    ----------
    name : str
        The name to convert

    Returns
    -------
    str
        The class name
    """
    #Make sure name field does not have spaces and every word is capitalized
    #There can be " " or "-" or "_" in the name so split by all of them
    name= name.replace("-", " ")
    name= name.replace("_", " ")
    name= name.replace("/", " ")
    name= name.replace("(", " ")
    name= name.replace(")", " ")
    name= name.replace("&", " and ")
    name_parts = name.split(" ")
    
    return "".join([part.capitalize() for part in name_parts])

def writeJinja2Template(templateEnv,template_name: str, output_file: str, fields: dict):
    """Write a Jinja2 template to a file

    Parameters
    ----------
    template_file : str
        The template file to use

    output_file : str
        The output file to write to

    fields : dict
        The fields to use in the template
    """

    #make sure output path exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    template = templateEnv.get_template(template_name)
    outputText = template.render(fields)

    #Jinja2 for loop is producing pythonic empty lines so remove lines with something else than newline for empty lines
    #outputText = "\n".join([line for line in outputText.split("\n") if line.strip() != ""])

    with open(output_file, "w") as f:
        logger.info(f"Writing {output_file}")
        f.write(outputText)


def stixToTactics(stix_data: MemoryStore, package_name: str, domain: str , verbose_class: bool = False, output_dir: str ="."):

    package_root_dir = os.path.join(output_dir,"src","main","java", package_name.replace(".", os.sep) )

    #Add Tactic to the base package name
    root_package_name = package_name
    package_name = f"{package_name}.tactic"

    package_dir = os.path.join(package_root_dir, "tactic" )
    os.makedirs(package_dir, exist_ok=True)

    tactics = stix_data.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = stixToDf.remove_revoked_deprecated(tactics)

    tactic_rows = []
    for tactic in tactics:
        tactic_rows.append(stixToDf.parseBaseStix(tactic))

    #Use Jinja2 to load and render the template
    templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
    templateEnv = jinja2.Environment(loader=templateLoader)
    tactic={}
    tactic["package_name"] = package_name
    tactic["root_package_name"] = root_package_name
    #Write the AbstractTactic.java
    writeJinja2Template(templateEnv, "AbstractTactic.jinja2", os.path.join(package_dir,"AbstractTactic.java"), tactic)
    
    for tactic in tactic_rows:
        tactic["domain"]= domain
        tactic["package_name"] = package_name
        tactic["root_package_name"] = root_package_name
        #Make sure name field does not have spaces and every word is capitalized
        tactic["class_name"] = nameToClassName(tactic["name"])

        if "description" in tactic:
            tactic["description_field"] = tactic["description"].replace("\\", "\\\\").replace('"', "'").replace("\n", "")
            tactic["description_lines"] = formatTextToLines(tactic["description_field"])

        if "detection" in tactic:
            tactic["detection_field"] = tactic["detection"].replace("\\", "\\\\").replace('"', "'").replace("\n", "")
            tactic["detection_lines"] = formatTextToLines(tactic["detection_field"])

        #Write the Tactic as Interface as techniques commonly can be present in multiple tactics
        writeJinja2Template(templateEnv, "Tactic.jinja2", os.path.join(package_dir,f"{tactic['class_name']}.java"), tactic)

        #Write the GenericTactic to be used in cases when specific technique is not known
        writeJinja2Template(templateEnv, "GenericTactic.jinja2", os.path.join(package_dir,f"Generic{tactic['class_name']}.java"), tactic)
            

def stixToTechniques(all_data_sources:SortedDict, all_defenses_bypassed:SortedDict ,all_platforms:SortedDict ,stix_data: MemoryStore,package_name: str, domain , verbose_class: bool = False, output_dir: str ="."):
    """Parse STIX techniques from the given data and write corresponding Java classes

    :param stix_data: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK stix_data corresponds to, e.g "enterprise-attack"
    """

    package_root_dir = os.path.join(output_dir,"src","main","java", package_name.replace(".", os.sep) )

    domain_bare = domain.replace("-attack", "")

    domain_package_dir = os.path.join(package_root_dir, domain_bare )

    techniques = stix_data.query([Filter("type", "=", "attack-pattern")])
    techniques =stixToDf.remove_revoked_deprecated(techniques)
    technique_rows = []

    tactics = stix_data.query([Filter("type", "=", "x-mitre-tactic")])
    tactics =stixToDf.remove_revoked_deprecated(tactics)
    tactic_names = {}
    for tactic in tactics:
        x_mitre_shortname = tactic["x_mitre_shortname"]
        tactic_names[x_mitre_shortname] = tactic["name"]

    all_sub_techniques = stix_data.query(
        [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "subtechnique-of"),
        ]
    )
    all_sub_techniques = MemoryStore(stix_data=all_sub_techniques)

    for technique in techniques:
        # get parent technique if sub-technique
        #pprint(technique)
        subtechnique = "x_mitre_is_subtechnique" in technique and technique["x_mitre_is_subtechnique"]
        if subtechnique:
            subtechnique_of = all_sub_techniques.query([Filter("source_ref", "=", technique["id"])])[0]
            parent = stix_data.get(subtechnique_of["target_ref"])

        # base STIX properties
        row =stixToDf.parseBaseStix(technique)

        # sub-technique properties
        if "kill_chain_phases" not in technique:
            attack_id = technique['external_references'][0]['external_id']
            logger.error(f"Skipping {attack_id} [{technique['id']}] because it does't have kill chain phases")
            continue
        tactic_shortnames = []
        for kcp in technique["kill_chain_phases"]:
            tactic_shortnames.append(kcp["phase_name"])

        technique_tactic_names = []
        implements = []
        for shortname in tactic_shortnames:
            tactic_display_name = tactic_names[shortname]
            technique_tactic_names.append(tactic_display_name)
            implements.append(f"{package_name}.tactic.{nameToClassName(tactic_display_name)}")
        row["tactics"] = ", ".join(sorted(technique_tactic_names))

        #remove the last comma and space, if they are present
        row["implements"] = False
        if len(implements) > 0:
            row["implements"] = ", ".join(sorted(implements))

        if "x_mitre_detection" in technique:
            row["detection"] = technique["x_mitre_detection"]
        if "x_mitre_platforms" in technique:
            row["platforms"] = ", ".join(sorted(technique["x_mitre_platforms"]))

        # domain specific fields -- ICS + Enterprise
        if domain in ["enterprise-attack", "ics-attack"]:
            if "x_mitre_data_sources" in technique:
                row["data sources"] = ", ".join(sorted(technique["x_mitre_data_sources"]))

        row["class_name"] = nameToClassName(f"{domain_bare} {technique['name']}")

        row["extends"] = f"{package_name}.MitreTTP"

        # domain specific fields -- enterprise
        if domain == "enterprise-attack":            
            row["is_sub-technique"] = subtechnique
            
            if subtechnique:                
                parent_name= nameToClassName(f"{domain_bare} {parent['name']}")
                parent_name_bare = nameToClassName(f"{parent['name']}")
                row["sub-technique of"] = parent["external_references"][0]["external_id"]
                row["extends"] = f"{package_name}.{domain_bare}.technique.{parent_name}"
                row["parent_name"] = parent_name
                row["parent_name_bare"] = parent_name_bare

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

        #modify the row dictionary keys so that they do not have spaces, as those can't be used in Jinja2 templates easily
        row = {key.replace(" ", "_"): value for key, value in row.items()}

        #Add all data source entries from row to all_data_sources
        data_source_keys = SortedSet()
        if "data_sources" in row:
            for data_source in row["data_sources"].split(", "):
                #convert key value to all uppercase and relace spaces with underscores
                data_source_key = data_source.upper().replace(" ", "_").replace(":", "_").replace("/", "_").replace("__", "_")
                data_source_key= remove_tautology(data_source_key)
                data_source_keys.add(data_source_key)
                all_data_sources[data_source_key] = data_source
        row["data_source_keys"] = data_source_keys
        
        defense_bypassed_keys = SortedSet()
        if "defenses_bypassed" in row:
            for defense_bypassed in row["defenses_bypassed"].split(", "):
                #convert key value to all uppercase and relace spaces with underscores
                defense_bypassed_key = defense_bypassed.upper().replace(" ", "_").replace(":", "_").replace("/", "_").replace("__", "_").replace("-", "_")
                defense_bypassed_key= remove_tautology(defense_bypassed_key)
                defense_bypassed_keys.add(defense_bypassed_key)
                all_defenses_bypassed[defense_bypassed_key] = defense_bypassed
        row["defense_bypassed_keys"] = defense_bypassed_keys

        platform_keys = SortedSet()
        if "platforms" in row:
            for platform in row["platforms"].split(", "):
                #convert key value to all uppercase and relace spaces with underscores
                platform_key = platform.upper().replace(" ", "_").replace(":", "_").replace("/", "_").replace("__", "_").replace("-", "_")
                platform_key= remove_tautology(platform_key)
                platform_keys.add(platform_key)
                all_platforms[platform_key] = platform
        row["platform_keys"] = platform_keys                
        
        if "description" in row:
            row["description_field"] = row["description"].replace("\\", "\\\\").replace('"', "'").replace("\n", "")
            row["description_lines"] = formatTextToLines(row["description_field"])

        if "detection" in row:
            row["detection_field"] = row["detection"].replace("\\", "\\\\").replace('"', "'").replace("\n", "")
            row["detection_lines"] = formatTextToLines(row["detection_field"])

        technique_rows.append(row)
    

    #Produce data sources enum from the collected data source items
    templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
    templateEnv = jinja2.Environment(loader=templateLoader)

    #split the package name into organization and package name f.ex org.mitre.attack -> org.mitre, attack
    organization, package_bare = package_name.rsplit(".", 1)

    if domain=="enterprise-attack":
        #Write common files for all domains when Enterprise domain is being processed
        writeJinja2Template(templateEnv, "pom.jinja2", os.path.join(output_dir,"pom.xml"), {"organization":organization,"package_bare":package_bare})
        writeJinja2Template(templateEnv, "MitreTTP.jinja2", os.path.join(package_root_dir,"MitreTTP.java"), {"package_name":package_name,"verbose_class":verbose_class})

    #Write or update enums
    writeJinja2Template(templateEnv, "MitreAttackDatasource.jinja2", os.path.join(package_root_dir,"MitreAttackDatasource.java"), {"all_data_sources":all_data_sources,"package_name":package_name})
    writeJinja2Template(templateEnv, "MitreAttackPlatform.jinja2", os.path.join(package_root_dir,"MitreAttackPlatform.java"), {"all_platforms":all_platforms,"package_name":package_name})
    writeJinja2Template(templateEnv, "MitreAttackDefensesBypassed.jinja2", os.path.join(package_root_dir,"MitreAttackDefensesBypassed.java"), {"all_defenses_bypassed":all_defenses_bypassed,"package_name":package_name})

    for technique in technique_rows:
        
        class_package_name = f"{package_name}.{domain_bare}.technique"
        class_package_postfix = "technique"

        if(technique.get("is_sub-technique",False)):
            class_package_name = f"{package_name}.{domain_bare}.technique.{technique['parent_name_bare'].lower()}"
            class_package_postfix = f"technique.{technique['parent_name_bare'].lower()}"


        package_dir = os.path.join(domain_package_dir, class_package_postfix.replace(".", os.sep) )
        os.makedirs(package_dir, exist_ok=True)

        technique["domain"]= domain
        technique["class_package_name"] = class_package_name
        technique["package_name"] = package_name
        technique["verbose_class"] = verbose_class

        #Use Jinja2 to load and render the template

        writeJinja2Template(templateEnv, "Technique.jinja2", os.path.join(package_dir,f"{technique['class_name']}.java"), technique)





        