from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get groups related to T1014
    technique_stix_id = 'attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b'
    groups_using_t1014 = mitre_attack_data.get_groups_using_technique(technique_stix_id)
    
    print(f"Groups using T1014 ({len(groups_using_t1014)}):")
    for g in groups_using_t1014:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
