import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get groups related to T1014
    technique_stix_id = "attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b"
    mitigations_mitigating_t1014 = mitre_attack_data.get_mitigations_mitigating_technique(technique_stix_id)

    print(f"Mitigations mitigating T1014 ({len(mitigations_mitigating_t1014)}):")
    for m in mitigations_mitigating_t1014:
        mitigation = m["object"]
        print(f"* {mitigation.name} ({mitre_attack_data.get_attack_id(mitigation.id)})")


if __name__ == "__main__":
    main()
