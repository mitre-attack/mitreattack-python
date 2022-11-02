from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all data components related to techniques
    datacomponents_detecting = mitre_attack_data.get_datacomponents_detecting_techniques()
    print(f"Data components detecting techniques ({len(datacomponents_detecting.keys())} techniques):")
    for id, datacomponents in datacomponents_detecting.items():
        print(f"* {id} - detected by {len(datacomponents)} {'data component' if len(datacomponents) == 1 else 'data components'}")

    # get data components detecting T1112
    datacomponents_detects_t1112 = datacomponents_detecting['attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4']
    print(f"\nData components detecting T1112 ({len(datacomponents_detects_t1112)}):")
    for d in datacomponents_detects_t1112:
        datacomponent = d['object']
        datasource = mitre_attack_data.get_object_by_stix_id(datacomponent.x_mitre_data_source_ref)
        print(f"* {datasource.name}: {datacomponent.name} ({mitre_attack_data.get_attack_id(datasource.id)})")


if __name__ == "__main__":
    main()
