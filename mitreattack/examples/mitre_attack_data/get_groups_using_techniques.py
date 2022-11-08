from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all groups related to techniques
    groups_using_techniques = mitre_attack_data.get_groups_using_techniques()
    print(f"Groups using techniques ({len(groups_using_techniques.keys())} techniques):")
    for id, groups in groups_using_techniques.items():
        print(f"* {id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")

    # get groups related to T1014
    groups_using_t1014 = groups_using_techniques['attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b']
    print(f"\nGroups using T1014 ({len(groups_using_t1014)}):")
    for g in groups_using_t1014:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
