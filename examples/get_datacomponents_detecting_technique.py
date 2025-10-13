import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get data components detecting T1112
    technique_stix_id = "attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4"
    datacomponents_detects_t1112 = mitre_attack_data.get_datacomponents_detecting_technique(technique_stix_id)

    print(f"Data components detecting T1112 ({len(datacomponents_detects_t1112)}):")
    for d in datacomponents_detects_t1112:
        datacomponent = d["object"]
        datasource = mitre_attack_data.get_object_by_stix_id(datacomponent.x_mitre_data_source_ref)
        print(f"* {datasource.name}: {datacomponent.name} ({mitre_attack_data.get_attack_id(datasource.id)})")


if __name__ == "__main__":
    main()
