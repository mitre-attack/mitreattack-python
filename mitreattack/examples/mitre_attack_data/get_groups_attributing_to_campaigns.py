from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all groups related to campaigns
    groups_attributing = mitre_attack_data.get_groups_attributing_to_campaigns()
    print(f"Groups attributing to campaigns ({len(groups_attributing.keys())} campaigns):")
    for id, groups in groups_attributing.items():
        print(f"* {id} - attributed to {len(groups)} {'group' if len(groups) == 1 else 'groups'}")

    # get groups related to C0011
    groups_attributing_to_c0011 = groups_attributing['campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac']
    print(f"\nGroups attributing to C0011 ({len(groups_attributing_to_c0011)}):")
    for g in groups_attributing_to_c0011:
        group = g['object']
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
