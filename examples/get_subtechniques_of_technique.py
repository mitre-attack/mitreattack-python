import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get the subtechniques of T1195
    technique_stix_id = "attack-pattern--3f18edba-28f4-4bb9-82c3-8aa60dcac5f7"
    subs_of_t1195 = mitre_attack_data.get_subtechniques_of_technique(technique_stix_id)

    print(f"Sub-techniques of T1195 ({len(subs_of_t1195)}):")
    for s in subs_of_t1195:
        sub = s["object"]
        print(f"* {sub.name} ({mitre_attack_data.get_attack_id(sub.id)})")


if __name__ == "__main__":
    main()
