""" MitreAttackData Library """

from itertools import chain
from stix2 import MemoryStore, Filter
from mitreattack.stix20.custom_attack_objects import StixObjectFactory, Matrix, Tactic, DataSource, DataComponent

class MitreAttackData:
    """ MitreAttackData object """

    def __init__(self, stix_filepath: str):
        """Initialize a MitreAttackData object

        Parameters
        ----------
        stix_file : str
            Filepath to a STIX 2.0 bundle
        """
        if not isinstance(stix_filepath, str):
            raise TypeError(f"Argument stix_filepath must be of type str, not {type(stix_filepath)}")

        self.src = MemoryStore()
        self.src.load_from_file(stix_filepath)

    ###################################
    # STIX Objects Section
    ###################################

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
                lambda x: x.get('x_mitre_deprecated', False) is False and x.get('revoked', False) is False,
                stix_objects
            )
        )

    def get_matrices(self) -> list:
        """Retrieve all matrix objects

        Returns
        -------
        list
            a list of Matrix objects
        """
        matrices = self.src.query([ Filter('type', '=', 'x-mitre-matrix') ])
        # since Matrix is a custom object, we need to reconstruct the query results
        return [Matrix(**m, allow_custom=True) for m in matrices]

    def get_tactics(self) -> list: # TODO optional flag to remove revoked/deprecated objects
        """Retrieve all tactic objects

        Returns
        -------
        list
            a list of Tactic objects
        """
        tactics = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])
        # since Tactic is a custom object, we need to reconstruct the query results
        return [Tactic(**t, allow_custom=True) for t in tactics]

    def get_techniques(self) -> list:
        """Retrieve all technique objects

        Returns
        -------
        list
            a list of AttackPattern objects
        """
        return self.src.query([ Filter('type', '=', 'attack-pattern') ])

    def get_mitigations(self) -> list:
        """Retrieve all mitigation objects

        Returns
        -------
        list
            a list of CourseOfAction objects
        """
        return self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])
    
    def get_groups(self) -> list:
        """Retrieve all group objects

        Returns
        -------
        list
            a list of IntrusionSet objects
        """
        return self.src.query([ Filter('type', '=', 'intrusion-set') ])

    def get_software(self) -> list:
        """Retrieve all software objects

        Returns
        -------
        list
            a list of Tool and Malware objects
        """
        return list(chain.from_iterable(
            self.src.query(f) for f in [
                Filter('type', '=', 'tool'), 
                Filter('type', '=', 'malware')
            ]
        ))
    
    def get_campaigns(self) -> list:
        """Retrieve all campaign objects

        Returns
        -------
        list
            a list of Campaign objects
        """
        return self.src.query([ Filter('type', '=', 'campaign') ])

    def get_datasources(self) -> list:
        """Retrieve all data source objects

        Returns
        -------
        list
            a list of DataSource objects
        """
        datasources = self.src.query([ Filter('type', '=', 'x-mitre-data-source') ])
        # since DataSource is a custom object, we need to reconstruct the query results
        return [DataSource(**ds, allow_custom=True) for ds in datasources]

    def get_datacomponents(self) -> list:
        """Retrieve all data component objects

        Returns
        -------
        list
            a list of DataComponent objects
        """
        datacomponents = self.src.query([ Filter('type', '=', 'x-mitre-data-component') ])
        # since DataComponent is a custom object, we need to reconstruct the query results
        return [DataComponent(**dc, allow_custom=True) for dc in datacomponents]

    def get_objects_by_content(self, content: str) -> list:
        """Retrieve objects by the content of their description

        Parameters
        ----------
        content : str
            the content string to search for

        Returns
        -------
        list
            a list of objects where the given content string appears in the description
        """
        return list(filter(lambda t: content.lower() in t.description.lower(), self.src))

    def get_techniques_by_platform(self, platform) -> list:
        filter = [
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_platforms', '=', platform)
        ]
        return self.src.query(filter)

    def get_datasources_by_platform(self, platform) -> list:
        filter = [
            Filter('type', '=', 'x-mitre-data-source'),
            Filter('x_mitre_platforms', '=', platform)
        ]
        return self.src.query(filter)
    
    ###################################
    # Get STIX Object by Value
    ###################################

    def get_object_by_stix_id(self, stix_id: str) -> object:
        """Retrieve a single object by STIX ID.

        Parameters
        ----------
        stix_id : str
            the STIX ID of the object to retrieve

        Returns
        -------
        stix2.v20.sdo._DomainObject | CustomStixObject
            the STIX Domain Object specified by the STIX ID
        """
        object = self.src.get(stix_id)
        return StixObjectFactory(object)

    def get_object_by_attack_id(self, attack_id: str) -> object:
        """Retrieve a single object by its ATT&CK ID

        Parameters
        ----------
        attack_id : str
            the ATT&CK ID of the object to retrieve

        Returns
        -------
        stix2.v20.sdo._DomainObject | CustomStixObject
            the STIX Domain Object specified by the ATT&CK ID
        """
        object = self.src.query([ Filter('external_references.external_id', '=', attack_id) ])[0]
        return StixObjectFactory(object)

    def get_object_by_name(self, name: str, type: str) -> object:
        """Retrieve an object by name

        Parameters
        ----------
        name : str
            the name of the object to retrieve
        type : str
            the STIX Domain Object type (e.g. attack-pattern)

        Returns
        -------
        stix2.v20.sdo._DomainObject | CustomStixObject
            the STIX Domain Object specified by the name and type
        """
        # TODO: if type = software (tool/malware)
        filter = [
            Filter('type', '=', type),
            Filter('name', '=', name)
        ]
        object = self.src.query(filter)
        return StixObjectFactory(object)

    def get_group_by_alias(self, alias: str) -> object:
        """Retrieve the group corresponding to a given alias

        Parameters
        ----------
        alias : str
            the alias of the group

        Returns
        -------
        stix2.v20.sdo.IntrusionSet
            the IntrusionSet object corresponding to the alias
        """
        filter = [
            Filter('type', '=', 'intrusion-set'),
            Filter('aliases', 'contains', alias)
        ]
        return self.src.query(filter)[0]

    def get_campaign_by_alias(self, alias: str) -> object:
        """Retrieve the campaign corresponding to a given alias

        Parameters
        ----------
        alias : str
            the alias of the campaign

        Returns
        -------
        stix2.v20.sdo.Campaign
            the Campaign object corresponding to the alias
        """
        filter = [
            Filter('type', '=', 'campaign'),
            Filter('aliases', 'contains', alias)
        ]
        return self.src.query(filter)[0]

    def get_software_by_alias(self, alias: str) -> object:
        """Retrieve the software corresponding to a given alias

        Parameters
        ----------
        alias : str
            the alias of the software

        Returns
        -------
        stix2.v20.sdo.Tool | stix2.v20.sdo.Malware
            the Tool or Malware object corresponding to the alias
        """
        tools = self.src.query([
            Filter('type', '=', 'tool'),
            Filter('x_mitre_aliases', 'contains', alias)
        ])
        malware = self.src.query([
            Filter('type', '=', 'malware'),
            Filter('x_mitre_aliases', 'contains', alias)
        ])
        return tools[0] or malware[0]

    ###################################
    # Relationship Section
    ###################################

    def get_related(self, source_type: str, relationship_type: str, target_type: str, reverse: bool = False) -> dict:
        """Build relationship mappings

        Parameters
        ----------
        source_type : str
            source type for the relationships, e.g. 'attack-pattern'
        relationship_type : str
            relationship type for the relationships, e.g. 'uses'
        target_type : str
            target type for the relationships, e.g. 'intrusion-set'
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
                            'relationship': relationship,
                            'id': relationship.target_ref
                        })
                    else:
                        id_to_related[relationship.target_ref].append({
                            'relationship': relationship,
                            'id': relationship.source_ref
                        })
                else:
                    # create a new entry
                    if not reverse:
                        id_to_related[relationship.source_ref] = [{
                            'relationship': relationship,
                            'id': relationship.target_ref
                        }]
                    else:
                        id_to_related[relationship.target_ref] = [{
                            'relationship': relationship,
                            'id': relationship.source_ref
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
                if not related['id'] in id_to_target:
                    continue  # targeting a revoked object
                value.append({
                    'object': id_to_target[related['id']], # BUG w/ retrieving data component objects here
                    'relationship': related['relationship']
                })
            output[stix_id] = value
        return output

    ###################################
    # Software/Group Relationships
    ###################################

    def get_software_used_by_groups(self) -> dict:
        """Get software used by groups

        Returns
        -------
        dict
            a mapping of group_id => {software, relationship} for each software used by the group and each software used 
            by campaigns attributed to the group
        """
        # get all software used by groups
        tools_used_by_group = self.get_related('intrusion-set', 'uses', 'tool')
        malware_used_by_group = self.get_related('intrusion-set', 'uses', 'malware')
        software_used_by_group = {**tools_used_by_group, **malware_used_by_group} # group_id -> {software, relationship}

        # get groups attributing to campaigns and all software used by campaigns
        software_used_by_campaign = self.get_related('campaign', 'uses', 'tool')
        malware_used_by_campaign = self.get_related('campaign', 'uses', 'malware')
        for id in malware_used_by_campaign:
            if id in software_used_by_campaign:
                software_used_by_campaign[id].extend(malware_used_by_campaign[id])
            else:
                software_used_by_campaign[id] = malware_used_by_campaign[id]
        campaigns_attributed_to_group = {
            'campaigns': self.get_related('campaign', 'attributed-to', 'intrusion-set', reverse=True), # group_id => {campaign, relationship}
            'software': software_used_by_campaign # campaign_id => {software, relationship}
        }

        for group_id in campaigns_attributed_to_group['campaigns']:
            software_used_by_campaigns = []
            # check if attributed campaign is using software
            for campaign in campaigns_attributed_to_group['campaigns'][group_id]:
                campaign_id = campaign['object']['id']
                if campaign_id in campaigns_attributed_to_group['software']:
                    software_used_by_campaigns.extend(campaigns_attributed_to_group['software'][campaign_id])
            
            # update software used by group to include software used by a groups attributed campaign
            if group_id in software_used_by_group:
                software_used_by_group[group_id].extend(software_used_by_campaigns)
            else:
                software_used_by_group[group_id] = software_used_by_campaigns
        return software_used_by_group

    def get_software_used_by_group_with_id(self, stix_id: str) -> list:
        """Get all software used by a single group

        Parameters
        ----------
        stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {software, relationship} for each software used by the group and each software used 
            by campaigns attributed to the group
        """
        software_used_by_groups = self.get_software_used_by_groups()
        return software_used_by_groups[stix_id] if stix_id in software_used_by_groups else []

    def get_groups_using_software(self) -> dict:
        """Get groups using software

        Returns
        -------
        dict
            a mapping of software_id => {group, relationship} for each group using the software and each attributed campaign
            using the software
        """
        # get all groups using software
        groups_using_tool = self.get_related('intrusion-set', 'uses', 'tool', reverse=True)
        groups_using_malware = self.get_related('intrusion-set', 'uses', 'malware', reverse=True)
        groups_using_software = {**groups_using_tool, **groups_using_malware} # software_id => {group, relationship}

        # get campaigns attributed to groups and all campaigns using software
        campaigns_using_software = self.get_related('campaign', 'uses', 'tool', reverse=True)
        campaigns_using_malware = self.get_related('campaign', 'uses', 'malware', reverse=True)
        for id in campaigns_using_malware:
            if id in campaigns_using_software:
                campaigns_using_software[id].extend(campaigns_using_malware[id])
            else:
                campaigns_using_software[id] = campaigns_using_malware[id]
        groups_attributing_to_campaigns = {
            'campaigns': campaigns_using_software,# software_id => {campaign, relationship}
            'groups': self.get_related('campaign', 'attributed-to', 'intrusion-set') # campaign_id => {group, relationship}
        }

        for software_id in groups_attributing_to_campaigns['campaigns']:
            groups_attributed_to_campaigns = []
            # check if campaign is attributed to group
            for campaign in groups_attributing_to_campaigns['campaigns'][software_id]:
                campaign_id = campaign['object']['id']
                if campaign_id in groups_attributing_to_campaigns['groups']:
                    groups_attributed_to_campaigns.extend(groups_attributing_to_campaigns['groups'][campaign_id])
            
            # update groups using software to include software used by a groups attributed campaign
            if software_id in groups_using_software:
                groups_using_software[software_id].extend(groups_attributed_to_campaigns)
            else:
                groups_using_software[software_id] = groups_attributed_to_campaigns
        return groups_using_software

    def get_groups_using_software_with_id(self, stix_id: str) -> list:
        """Get all groups using a single software

        Parameters
        ----------
        stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {group, relationship} for each group using the software and each attributed campaign
            using the software
        """
        groups_using_software = self.get_groups_using_software()
        return groups_using_software[stix_id] if stix_id in groups_using_software else []

    ###################################
    # Software/Campaign Relationships
    ###################################

    def get_software_used_by_campaigns(self) -> dict:
        """Get software used by campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {software, relationship} for each software used by the campaign
        """
        tools_used_by_campaign = self.get_related('campaign', 'uses', 'tool')
        malware_used_by_campaign = self.get_related('campaign', 'uses', 'malware')
        return {**tools_used_by_campaign, **malware_used_by_campaign}

    def get_software_used_by_campaigns_with_id(self, stix_id: str) -> list:
        """Get all software used by a single campaign

        Parameters
        ----------
        stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {software, relationship} for each software used by the campaign
        """
        software_used_by_campaigns = self.get_software_used_by_campaigns()
        return software_used_by_campaigns[stix_id] if stix_id in software_used_by_campaigns else []

    def get_campaigns_using_software(self) -> dict:
        """Get campaigns using software

        Returns
        -------
        dict
            a mapping of software_id => {campaign, relationship} for each campaign using the software
        """
        campaigns_using_tool = self.get_related('campaign', 'uses', 'tool', reverse=True)
        campaigns_using_malware = self.get_related('campaign', 'uses', 'malware', reverse=True)
        return {**campaigns_using_tool, **campaigns_using_malware}

    def get_campaigns_using_software_with_id(self, stix_id: str) -> list:
        """Get all campaigns using a single software

        Parameters
        ----------
        stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {campaign, relationship} for each campaign using the software
        """
        campaigns_using_software = self.get_campaigns_using_software()
        return campaigns_using_software[stix_id] if stix_id in campaigns_using_software else []


    ###################################
    # Campaign/Group Relationships
    ###################################

    def get_groups_attributing_to_campaigns(self) -> dict:
        """Get groups attributing to campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {group, relationship} for each group attributing to the campaign
        """
        return self.get_related('campaign', 'attributed-to', 'intrusion-set')
    
    def get_groups_attributing_to_campaign_with_id(self, stix_id: str) -> list:
        """Get all groups attributing to a single campaign

        Parameters
        ----------
        stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {group, relationship} for each group attributing to the campaign
        """
        groups_attributing_to_campaigns = self.get_groups_attributing_to_campaigns()
        return groups_attributing_to_campaigns[stix_id] if stix_id in groups_attributing_to_campaigns else []

    def get_campaigns_attributed_to_groups(self) -> dict:
        """Get campaigns attributed to groups

        Returns
        -------
        dict
            a mapping of group_id => {campaign, relationship} for each campaign attributed to the group
        """
        return self.get_related('campaign', 'attributed-to', 'intrusion-set', reverse=True)

    def get_campaigns_attributed_to_group_with_id(self, stix_id: str) -> list:
        """Get all campaigns attributed to a single group

        Parameters
        ----------
        stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {campaign, relationship} for each campaign attributed to the group
        """

    ###################################
    # Technique/Group Relationships
    ###################################

    def get_techniques_used_by_groups(self) -> dict:
        """Get techniques used by groups

        Returns
        -------
        dict
            a mapping of group_id => {technique, relationship} for each technique used by the group and 
            each technique used by campaigns attributed to the group
        """
        # get all techniques used by groups
        techniques_used_by_groups = self.get_related('intrusion-set', 'uses', 'attack-pattern') # group_id => {technique, relationship}

        # get groups attributing to campaigns and all techniques used by campaigns
        campaigns_attributed_to_group = {
            'campaigns': self.get_related('campaign', 'attributed-to', 'intrusion-set', reverse=True), # group_id => {campaign, relationship}
            'techniques': self.get_related('campaign', 'uses', 'attack-pattern') # campaign_id => {technique, relationship}
        }

        for group_id in campaigns_attributed_to_group['campaigns']:
            techniques_used_by_campaigns = []
            # check if attributed campaign is using technique
            for campaign in campaigns_attributed_to_group['campaigns'][group_id]:
                campaign_id = campaign['object']['id']
                if campaign_id in campaigns_attributed_to_group['techniques']:
                    techniques_used_by_campaigns.extend(campaigns_attributed_to_group['techniques'][campaign_id])

            # update techniques used by groups to include techniques used by a groups attributed campaign
            if group_id in techniques_used_by_groups:
                techniques_used_by_groups[group_id].extend(techniques_used_by_campaigns)
            else:
                techniques_used_by_groups[group_id] = techniques_used_by_campaigns
        return techniques_used_by_groups

    def get_techniques_used_by_group_with_id(self, stix_id: str) -> list:
        """Get all techniques used by a single group

        Parameters
        ----------
        stix_id : str
            the STIX ID of the group

        Returns
        -------
        list
            a list of {technique, relationship} for each technique used by the group and 
            each technique used by campaigns attributed to the group
        """
        techniques_used_by_groups = self.get_techniques_used_by_groups()
        return techniques_used_by_groups[stix_id] if stix_id in techniques_used_by_groups else []

    def get_groups_using_techniques(self) -> dict:
        """Get groups using techniques

        Returns
        -------
        dict
            a mapping of technique_id => {group, relationship} for each group using the technique and each campaign attributed to 
            groups using the technique
        """
        # get all groups using techniques
        groups_using_techniques = self.get_related('intrusion-set', 'uses', 'attack-pattern', reverse=True) # technique_id => {group, relationship}

        # get campaigns attributed to groups and all campaigns using techniques
        groups_attributing_to_campaigns = {
            'campaigns': self.get_related('campaign', 'uses', 'attack-pattern', reverse=True), # technique_id => {campaign, relationship}
            'groups': self.get_related('campaign', 'attributed-to', 'intrusion-set') # campaign_id => {group, relationship}
        }

        for technique_id in groups_attributing_to_campaigns['campaigns']:
            campaigns_attributed_to_group = []
            # check if campaign is attributed to group
            for campaign in groups_attributing_to_campaigns['campaigns'][technique_id]:
                campaign_id = campaign['object']['id']
                if campaign_id in groups_attributing_to_campaigns['groups']:
                    campaigns_attributed_to_group.extend(groups_attributing_to_campaigns['groups'][campaign_id])
            
            # update groups using techniques to include techniques used by a groups attributed campaign
            if technique_id in groups_using_techniques:
                groups_using_techniques[technique_id].extend(campaigns_attributed_to_group)
            else:
                groups_using_techniques[technique_id] = campaigns_attributed_to_group
        return groups_using_techniques

    def get_groups_using_technique_with_id(self, stix_id: str) -> list:
        """Get all groups using a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {group, relationship} for each group using the technique and each campaign attributed to 
            groups using the technique
        """
        groups_using_techniques = self.get_groups_using_techniques()
        return groups_using_techniques[stix_id] if stix_id in groups_using_techniques else []

    ###################################
    # Technique/Campaign Relationships
    ###################################

    def get_techniques_used_by_campaigns(self) -> dict:
        """Get techniques used by campaigns

        Returns
        -------
        dict
            a mapping of campaign_id => {technique, relationship} for each technique used by the campaign
        """
        return self.get_related('campaign', 'uses', 'attack-pattern')

    def get_techniques_used_by_campaign_with_id(self, stix_id: str) -> list:
        """Get all techniques used by a single campaign

        Parameters
        ----------
        stix_id : str
            the STIX ID of the campaign

        Returns
        -------
        list
            a list of {technique, relationship} for each technique used by the campaign
        """
        techniques_used_by_campaigns = self.get_techniques_used_by_campaigns()
        return techniques_used_by_campaigns[stix_id] if stix_id in techniques_used_by_campaigns else []

    def get_campaigns_using_techniques(self) -> dict:
        """Get campaigns using techniques

        Returns
        -------
        dict
            a mapping of technique_id => {campaign, relationship} for each campaign using the technique
        """
        return self.get_related('campaign', 'uses', 'attack-pattern', reverse=True)

    def get_campaigns_using_technique_with_id(self, stix_id: str) -> list:
        """Get all campaigns using a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {campaign, relationship} for each campaign using the technique
        """
        campaigns_using_techniques = self.get_campaigns_using_techniques()
        return campaigns_using_techniques[stix_id] if stix_id in campaigns_using_techniques else []

    ###################################
    # Technique/Software Relationships
    ###################################

    def get_techniques_used_by_software(self) -> dict:
        """Get techniques used by software

        Returns
        -------
        dict
            a mapping of software_id => {technique, relationship} for each technique used by the software
        """
        techniques_by_tool = self.get_related('tool', 'uses', 'attack-pattern')
        techniques_by_malware = self.get_related('malware', 'uses', 'attack-pattern')
        return {**techniques_by_tool, **techniques_by_malware}

    def get_techniques_used_by_software_with_id(self, stix_id: str) -> list:
        """Get all techniques used by a single software

        Parameters
        ----------
        stix_id : str
            the STIX ID of the software

        Returns
        -------
        list
            a list of {technique, relationship} for each technique used by the software
        """
        techniques_used_by_software = self.get_techniques_used_by_software()
        return techniques_used_by_software[stix_id] if stix_id in techniques_used_by_software else []

    def get_software_using_techniques(self) -> dict:
        """Get software using technique

        Returns
        -------
        dict
            a mapping of technique_id => {software, relationship} for each software using the technique
        """
        tools_by_technique_id = self.get_related('tool', 'uses', 'attack-pattern', reverse=True)
        malware_by_technique_id = self.get_related('malware', 'uses', 'attack-pattern', reverse=True)
        return {**tools_by_technique_id, **malware_by_technique_id}

    def get_software_using_technique_with_id(self, stix_id: str) -> list:
        """Get all software using a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {software, relationship} for each software using the technique
        """
        software_using_techniques = self.get_software_using_techniques()
        return software_using_techniques[stix_id] if stix_id in software_using_techniques else []

    ###################################
    # Technique/Mitigation Relationships
    ###################################

    def get_techniques_mitigated_by_mitigations(self) -> dict:
        """Get techniques mitigated by mitigations

        Returns
        -------
        dict
            a mapping of mitigation_id => {technique, relationship} for each technique mitigated by the mitigation
        """
        return self.get_related('course-of-action', 'mitigates', 'attack-pattern')
    
    def get_techniques_mitigated_by_mitigation_with_id(self, stix_id: str) -> list:
        """Get all techniques being mitigated by a single mitigation

        Parameters
        ----------
        stix_id : str
            the STIX ID of the mitigation

        Returns
        -------
        list
            a list of {technique, relationship} for each technique mitigated by the mitigation
        """
        techniques_mitigated_by_mitigations = self.get_techniques_mitigated_by_mitigations()
        return techniques_mitigated_by_mitigations[stix_id] if stix_id in techniques_mitigated_by_mitigations else []

    def get_mitigations_mitigating_techniques(self) -> dict:
        """Get mitigations mitigating techniques

        Returns
        -------
        dict
            a mapping of technique_id => {mitigation, relationship} for each mitigation mitigating the technique
        """
        return self.get_related('course-of-action', 'mitigates', 'attack-pattern', reverse=True)

    def get_mitigations_mitigating_technique_with_id(self, stix_id: str) -> list:
        """Get all mitigations mitigating a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {mitigation, relationship} for each mitigation mitigating the technique
        """

    ###################################
    # Technique/Subtechnique Relationships
    ###################################

    def get_parent_technique_of_subtechniques(self) -> dict:
        """Get parent techniques of subtechniques

        Returns
        -------
        dict
            a mapping of subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique
        """
        return self.get_related('attack-pattern', 'subtechnique-of', 'attack-pattern')[0]

    def get_parent_technique_of_subtechnique_with_id(self, stix_id: str) -> dict:
        """Get the parent technique of a single subtechnique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the subtechnique

        Returns
        -------
        dict
            {parent technique, relationship} describing the parent technique of the subtechnique
        """
        parent_techniques_of_subtechniques = self.get_parent_technique_of_subtechniques()
        return parent_techniques_of_subtechniques[stix_id] if stix_id in parent_techniques_of_subtechniques else []

    def get_subtechniques_of_techniques(self) -> dict:
        """Get subtechniques of techniques

        Returns
        -------
        dict
            a mapping of technique_id => {subtechnique, relationship} for each subtechnique of the technique
        """
        return self.get_related('attack-pattern', 'subtechnique-of', 'attack-pattern', reverse=True)

    def get_subtechniques_of_technique_with_id(self, stix_id: str) -> list:
        """Get all subtechniques of a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {subtechnique, relationship} for each subtechnique of the technique
        """
        subtechniques_of_techniques = self.get_subtechniques_of_techniques()
        return subtechniques_of_techniques[stix_id] if stix_id in subtechniques_of_techniques else []

    ###################################
    # Technique/Data Component Relationships
    ###################################

    def get_techniques_detected_by_datacomponents(self) -> dict:
        """Get techniques detected by data components
        Returns
        -------
        dict
            a mapping of datacomponent_id => {technique, relationship} describing the detections of the data component
        """
        return self.get_related('x-mitre-data-component', 'detects', 'attack-pattern')
    
    def get_techniques_detected_by_datacomponent_with_id(self, stix_id: str) -> list:
        """Get all techniques detected by a single data component

        Parameters
        ----------
        stix_id : str
            the STIX ID of the data component

        Returns
        -------
        list
            a list of {technique, relationship} describing the detections of the data component
        """
        techniques_detected_by_datacomponents = self.get_techniques_detected_by_datacomponents()
        return techniques_detected_by_datacomponents[stix_id] if stix_id in techniques_detected_by_datacomponents else []

    def get_datacomponents_detecting_techniques(self) -> dict:
        """Get data components detecting techniques

        Returns
        -------
        dict
            a mapping of technique_id => {datacomponent, relationship} describing the data components that can detect the technique
        """
        return self.get_related('x-mitre-data-component', 'detects', 'attack-pattern', reverse=True)

    def get_datacomponents_detecting_technique_with_id(self, stix_id: str) -> list:
        """Get all data components detecting a single technique

        Parameters
        ----------
        stix_id : str
            the STIX ID of the technique

        Returns
        -------
        list
            a list of {datacomponent, relationship} describing the data components that can detect the technique
        """
        datacomponents_detecting_techniques = self.get_datacomponents_detecting_techniques()
        return datacomponents_detecting_techniques[stix_id] if stix_id in datacomponents_detecting_techniques else []
