import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get techniques mitigated by M1020
    mitigation_stix_id = "course-of-action--7bb5fae9-53ad-4424-866b-f0ea2a8b731d"
    techniques_mitigated_by_m1020 = mitre_attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)

    print(f"Techniques mitigated by M1020 ({len(techniques_mitigated_by_m1020)}):")
    for t in techniques_mitigated_by_m1020:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
