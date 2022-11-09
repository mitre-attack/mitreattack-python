from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get techniques used by G0019
    group_stix_id = 'intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050'
    techniques_used_by_g0019 = mitre_attack_data.get_techniques_used_by_group(group_stix_id)

    print(f"Techniques used by G0019 ({len(techniques_used_by_g0019)}):")
    for t in techniques_used_by_g0019:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
