""" MitreAttackData Library """

from stix2 import MemoryStore, Filter

class InvalidInput(Exception):
    pass

class MitreAttackData:
    """ MitreAttackData object """

    def __init__(self, stix_file: str):
        """Initialize a MitreAttackData object

        Parameters
        ----------
        stix_file : str
            Filepath to a STIX 2.0 bundle
        """
        if not isinstance(stix_file, str):
            raise InvalidInput

        self.src = MemoryStore()
        self.src.load_from_file(stix_file)

    def remove_revoked_deprecated(self, stix_objects: list) -> list:
        """Remove revoked or deprecated objects from queries made to the data source

        Parameters
        ----------
        stix_objects : list
            list of STIX objects from a query made to the data source

        Returns
        -------
        list
            list of STIX objects with revoked and deprecated objects filtered out
        """
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects
            )
        )

    def get_related(self, source_type: str, relationship_type: str, target_type: str, reverse: bool = False) -> dict:
        """Build relationship mappings

        Parameters
        ----------
        source_type : str
            source type for the relationships, e.g. "attack-pattern"
        relationship_type : str
            relationship type for the relationships, e.g. "uses"
        target_type : str
            target type for the relationships, e.g. "intrusion-set"
        reverse : bool, optional
            build reverse mapping of target to source, by default False

        Returns
        -------
        dict
            if reverse=False, relationship mapping of source_object_id => [{target_object, relationship}]; 
            if reverse=True, relationship mapping of target_object_id => [{source_object, relationship}]
        """
        relationships = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', relationship_type),
            Filter('revoked', '=', False),
        ])
        relationships = self.remove_revoked_deprecated(relationships)

        # stix_id => [ { relationship, related_object_id } for each related object ]
        id_to_related = {}

        # build the dict
        for relationship in relationships:
            if source_type in relationship.source_ref and target_type in relationship.target_ref:
                if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                    # append to existing entry
                    if not reverse:
                        id_to_related[relationship.source_ref].append({
                            "relationship": relationship,
                            "id": relationship.target_ref
                        })
                    else:
                        id_to_related[relationship.target_ref].append({
                            "relationship": relationship,
                            "id": relationship.source_ref
                        })
                else:
                    # create a new entry
                    if not reverse:
                        id_to_related[relationship.source_ref] = [{
                            "relationship": relationship,
                            "id": relationship.target_ref
                        }]
                    else:
                        id_to_related[relationship.target_ref] = [{
                            "relationship": relationship,
                            "id": relationship.source_ref
                        }]

        # all objects of relevant type
        if not reverse:
            targets = self.src.query([
                Filter('type', '=', target_type),
                Filter('revoked', '=', False)
            ])
        else:
            targets = self.src.query([
                Filter('type', '=', source_type),
                Filter('revoked', '=', False)
            ])

        # build lookup of stixID to stix object
        id_to_target = {}
        for target in targets:
            id_to_target[target.id] = target

        # build final output mappings
        output = {}
        for stix_id in id_to_related:
            value = []
            for related in id_to_related[stix_id]:
                if not related["id"] in id_to_target:
                    continue  # targeting a revoked object
                value.append({
                    "object": id_to_target[related["id"]],
                    "relationship": related["relationship"]
                })
            output[stix_id] = value
        return output

    # software:group
    def get_software_used_by_groups(self) -> dict:
        """Get software used by groups

        Returns
        -------
        dict
            a mapping of group_id => {software, relationship} for each software used by the group and each software used 
            by campaigns attributed to the group
        """
        # get all software used by groups
        tools_used_by_group = self.get_related(self.src, "intrusion-set", "uses", "tool")
        malware_used_by_group = self.get_related(self.src, "intrusion-set", "uses", "malware")
        software_used_by_group = {**tools_used_by_group, **malware_used_by_group} # group_id -> {software, relationship}

        # get groups attributing to campaigns and all software used by campaigns
        software_used_by_campaign = self.get_related(self.src, "campaign", "uses", "tool")
        malware_used_by_campaign = self.get_related(self.src, "campaign", "uses", "malware")
        for id in malware_used_by_campaign:
            if id in software_used_by_campaign:
                software_used_by_campaign[id].extend(malware_used_by_campaign[id])
            else:
                software_used_by_campaign[id] = malware_used_by_campaign[id]
        campaigns_attributed_to_group = {
            "campaigns": self.get_related(self.src, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
            "software": software_used_by_campaign # campaign_id => {software, relationship}
        }

        for group_id in campaigns_attributed_to_group["campaigns"]:
            software_used_by_campaigns = []
            # check if attributed campaign is using software
            for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
                campaign_id = campaign["object"]["id"]
                if campaign_id in campaigns_attributed_to_group["software"]:
                    software_used_by_campaigns.extend(campaigns_attributed_to_group["software"][campaign_id])
            
            # update software used by group to include software used by a groups attributed campaign
            if group_id in software_used_by_group:
                software_used_by_group[group_id].extend(software_used_by_campaigns)
            else:
                software_used_by_group[group_id] = software_used_by_campaigns
        return software_used_by_group

    def get_groups_using_software(self) -> dict:
        """Get groups using software

        Returns
        -------
        dict
            a mapping of software_id => {group, relationship} for each group using the software and each software used by 
            attributed campaigns
        """
        # get all groups using software
        groups_using_tool = self.get_related(self.src, "intrusion-set", "uses", "tool", reverse=True)
        groups_using_malware = self.get_related(self.src, "intrusion-set", "uses", "malware", reverse=True)
        groups_using_software = {**groups_using_tool, **groups_using_malware} # software_id => {group, relationship}

        # get campaigns attributed to groups and all campaigns using software
        campaigns_using_software = self.get_related(self.src, "campaign", "uses", "tool", reverse=True)
        campaigns_using_malware = self.get_related(self.src, "campaign", "uses", "malware", reverse=True)
        for id in campaigns_using_malware:
            if id in campaigns_using_software:
                campaigns_using_software[id].extend(campaigns_using_malware[id])
            else:
                campaigns_using_software[id] = campaigns_using_malware[id]
        groups_attributing_to_campaigns = {
            "campaigns": campaigns_using_software,# software_id => {campaign, relationship}
            "groups": self.get_related(self.src, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
        }

        for software_id in groups_attributing_to_campaigns["campaigns"]:
            groups_attributed_to_campaigns = []
            # check if campaign is attributed to group
            for campaign in groups_attributing_to_campaigns["campaigns"][software_id]:
                campaign_id = campaign["object"]["id"]
                if campaign_id in groups_attributing_to_campaigns["groups"]:
                    groups_attributed_to_campaigns.extend(groups_attributing_to_campaigns["groups"][campaign_id])
            
            # update groups using software to include software used by a groups attributed campaign
            if software_id in groups_using_software:
                groups_using_software[software_id].extend(groups_attributed_to_campaigns)
            else:
                groups_using_software[software_id] = groups_attributed_to_campaigns
        return groups_using_software

    # software:campaign
    def get_software_used_by_campaigns(self) -> dict:
        """Get software used by campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {software, relationship} for each software used by the campaign
        """
        tools_used_by_campaign = self.get_related(self.src, "campaign", "uses", "tool")
        malware_used_by_campaign = self.get_related(self.src, "campaign", "uses", "malware")
        return {**tools_used_by_campaign, **malware_used_by_campaign}

    def get_campaigns_using_software(self) -> dict:
        """Get campaigns using software

        Returns
        -------
        dict
            a mapping of software_id => {campaign, relationship} for each campaign using the software
        """
        campaigns_using_tool = self.get_related(self.src, "campaign", "uses", "tool", reverse=True)
        campaigns_using_malware = self.get_related(self.src, "campaign", "uses", "malware", reverse=True)
        return {**campaigns_using_tool, **campaigns_using_malware}

    # campaign:group
    def get_groups_attributing_to_campaigns(self) -> dict:
        """Get groups attributing to campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {group, relationship} for each group attributing to the campaign
        """
        return self.get_related(self.src, "campaign", "attributed-to", "intrusion-set")

    def get_campaigns_attributed_to_groups(self) -> dict:
        """Get campaigns attributed to groups

        Returns
        -------
        dict
            a mapping of group_id => {campaign, relationship} for each campaign attributed to the group
        """
        return self.get_related(self.src, "campaign", "attributed-to", "intrusion-set", reverse=True)

    # technique:group
    def get_techniques_used_by_groups(self) -> dict:
        """Get techniques used by groups

        Returns
        -------
        dict
            a mapping of group_id => {technique, relationship} for each technique used by the group and 
            each technique used by campaigns attributed to the group
        """
        # get all techniques used by groups
        techniques_used_by_groups = self.get_related(self.src, "intrusion-set", "uses", "attack-pattern") # group_id => {technique, relationship}

        # get groups attributing to campaigns and all techniques used by campaigns
        campaigns_attributed_to_group = {
            "campaigns": self.get_related(self.src, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
            "techniques": self.get_related(self.src, "campaign", "uses", "attack-pattern") # campaign_id => {technique, relationship}
        }

        for group_id in campaigns_attributed_to_group["campaigns"]:
            techniques_used_by_campaigns = []
            # check if attributed campaign is using technique
            for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
                campaign_id = campaign["object"]["id"]
                if campaign_id in campaigns_attributed_to_group["techniques"]:
                    techniques_used_by_campaigns.extend(campaigns_attributed_to_group["techniques"][campaign_id])

            # update techniques used by groups to include techniques used by a groups attributed campaign
            if group_id in techniques_used_by_groups:
                techniques_used_by_groups[group_id].extend(techniques_used_by_campaigns)
            else:
                techniques_used_by_groups[group_id] = techniques_used_by_campaigns
        return techniques_used_by_groups

    def get_groups_using_techniques(self) -> dict:
        """Get groups using techniques

        Returns
        -------
        dict
            a mapping of technique_id => {group, relationship} for each group using the technique and each campaign attributed to 
            groups using the technique
        """
        # get all groups using techniques
        groups_using_techniques = self.get_related(self.src, "intrusion-set", "uses", "attack-pattern", reverse=True) # technique_id => {group, relationship}

        # get campaigns attributed to groups and all campaigns using techniques
        groups_attributing_to_campaigns = {
            "campaigns": self.get_related(self.src, "campaign", "uses", "attack-pattern", reverse=True), # technique_id => {campaign, relationship}
            "groups": self.get_related(self.src, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
        }

        for technique_id in groups_attributing_to_campaigns["campaigns"]:
            campaigns_attributed_to_group = []
            # check if campaign is attributed to group
            for campaign in groups_attributing_to_campaigns["campaigns"][technique_id]:
                campaign_id = campaign["object"]["id"]
                if campaign_id in groups_attributing_to_campaigns["groups"]:
                    campaigns_attributed_to_group.extend(groups_attributing_to_campaigns["groups"][campaign_id])
            
            # update groups using techniques to include techniques used by a groups attributed campaign
            if technique_id in groups_using_techniques:
                groups_using_techniques[technique_id].extend(campaigns_attributed_to_group)
            else:
                groups_using_techniques[technique_id] = campaigns_attributed_to_group
        return groups_using_techniques

    # technique:campaign
    def get_techniques_used_by_campaigns(self) -> dict:
        """Get techniques used by campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {technique, relationship} for each technique used by the campaign
        """
        return self.get_related(self.src, "campaign", "uses", "attack-pattern")

    def get_campaigns_using_techniques(self) -> dict:
        """Get campaigns using techniques

        Returns
        -------
        dict
            a mapping of technique_id => {campaign, relationship} for each campaign using the technique
        """
        return self.get_related(self.src, "campaign", "uses", "attack-pattern", reverse=True)

    # technique:software
    def get_techniques_used_by_software(self) -> dict:
        """Get techniques used by software

        Returns
        -------
        dict
            a mapping of software_id => {technique, relationship} for each technique used by the software
        """
        techniques_by_tool = self.get_related(self.src, "tool", "uses", "attack-pattern")
        techniques_by_malware = self.get_related(self.src, "malware", "uses", "attack-pattern")
        return {**techniques_by_tool, **techniques_by_malware}

    def get_software_using_techniques(self) -> dict:
        """Get software using technique

        Returns
        -------
        dict
            a mapping of technique_id => {software, relationship} for each software using the technique
        """
        tools_by_technique_id = self.get_related(self.src, "tool", "uses", "attack-pattern", reverse=True)
        malware_by_technique_id = self.get_related(self.src, "malware", "uses", "attack-pattern", reverse=True)
        return {**tools_by_technique_id, **malware_by_technique_id}

    # technique:mitigation
    def get_mitigations_mitigate_techniques(self) -> dict:
        """Get mitigations that mitigate techniques

        Returns
        -------
        dict
            a mapping of mitigation_id => {technique, relationship} for each technique mitigated by the mitigation
        """
        return self.get_related(self.src, "course-of-action", "mitigates", "attack-pattern", reverse=False)

    def get_techniques_mitigated_by_mitigations(self) -> dict:
        """Get techniques mitigated by mitigations

        Returns
        -------
        dict
            a mapping of technique_id => {mitigation, relationship} for each mitigation of the technique
        """
        return self.get_related(self.src, "course-of-action", "mitigates", "attack-pattern", reverse=True)

    # technique:sub-technique
    def get_subtechniques_of(self) -> dict:
        """Get technique subtechniques

        Returns
        -------
        dict
            a mapping of technique_id => {subtechnique, relationship} for each subtechnique of the technique
        """
        return self.get_related(self.src, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)

    def get_parent_technique_of(self) -> dict:
        """Get parent technique of subtechniques

        Returns
        -------
        dict
            a mapping of subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique
        """
        return self.get_related(self.src, "attack-pattern", "subtechnique-of", "attack-pattern")[0]

    # technique:data-component
    def get_datacomponents_detect_techniques(self) -> dict:
        """Get data components that detect techniques
        Returns
        -------
        dict
            a mapping of datacomponent_id => {technique, relationship} describing the detections of each data component
        """
        return self.get_related(self.src, "x-mitre-data-component", "detects", "attack-pattern")

    def get_techniques_detected_by_datacomponents(self) -> dict:
        """Get techniques detected by data components

        Returns
        -------
        dict
            a mapping of technique_id => {datacomponent, relationship} describing the data components that can detect the technique
        """
        return self.get_related(self.src, "x-mitre-data-component", "detects", "attack-pattern", reverse=True)
