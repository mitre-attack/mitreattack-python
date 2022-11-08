from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all techniques related to groups
    techniques_used_by_groups = mitre_attack_data.get_techniques_used_by_groups()
    print(f"Techniques used by groups ({len(techniques_used_by_groups.keys())} groups):")
    for id, techniques_used in techniques_used_by_groups.items():
        print(f"* {id} - {len(techniques_used)} {'technique' if len(techniques_used) == 1 else 'techniques'} used")

    # get techniques used by G0019
    techniques_used_by_g0019 = techniques_used_by_groups['intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050']
    print(f"\nTechniques used by G0019 ({len(techniques_used_by_g0019)}):")
    for t in techniques_used_by_g0019:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
