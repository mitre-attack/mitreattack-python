from stix2 import Filter, datastore
from mitreattack.navlayers.generators.usage_generator import UsageLayerGenerator
from mitreattack.navlayers.core.exceptions import typeChecker, categoryChecker
from mitreattack.navlayers.generators.gen_helpers import remove_revoked_depreciated, get_attack_id
from tqdm import tqdm


class BatchGenerator:
    def __init__(self, source, domain='enterprise', local=None):
        """
        Initialize the Generator
        :param source: Which source to use for data (local, taxii [server], or [remote] ATT&CK Workbench)
        :param domain: Which matrix to use during generation
        :param local: Optional path to local data
        """
        self.usage_handle = UsageLayerGenerator(source, domain, local)
        self.mapping = dict(group=[Filter('type', '=', 'intrusion-set')],
                            software=[Filter('type', '=', 'malware'), Filter('type', '=', 'tool')],
                            mitigation=[Filter('type', '=', 'course-of-action')])

    def generate_layers(self, layers_type):
        """
        Generate and return a collection of layers for all objects of a given type
        :param layers_type: the type of object to generate layers for (group, software, or mitigation)
        :return: dictionary of generated layer objects, referenced by STIX-ID
        """
        typeChecker(type(self).__name__, layers_type, str, "type")
        categoryChecker(type(self).__name__, layers_type, ["group", "software", "mitigation"], "type")
        produced = dict()
        object_listing = remove_revoked_depreciated(self.usage_handle.source_handle.query(self.mapping[layers_type]))
        for entry in tqdm(object_listing, desc=f"building {layers_type} matrices"):
            try:
                produced[entry.id] = self.usage_handle.generate_layer(get_attack_id(entry))
            except datastore.DataSourceError as e:
                print(f"WARNING - unable to generate layer for {(entry.id, entry.name)}. "
                      f"Specifically, generator encountered {e}. Continuing...")
        return produced
