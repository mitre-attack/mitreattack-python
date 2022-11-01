from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all techniques related to mitigations
    techniques_mitigated = mitre_attack_data.get_techniques_mitigated_by_mitigations()
    print(f"Techniques mitigated by mitigations ({len(techniques_mitigated.keys())} mitigations):")
    for id, techniques in techniques_mitigated.items():
        print(f"* {id} - mitigates {len(techniques)} {'technique' if len(techniques) == 1 else 'techniques'}")

    # get techniques mitigated by M1020
    techniques_mitigated_by_m1020 = techniques_mitigated['course-of-action--7bb5fae9-53ad-4424-866b-f0ea2a8b731d']
    print(f"\nTechniques mitigated by M1020 ({len(techniques_mitigated_by_m1020)}):")
    for t in techniques_mitigated_by_m1020:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
