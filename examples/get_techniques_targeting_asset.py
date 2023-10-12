from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("ics-attack.json")

    # get techniques targeting A0004
    asset_stix_id = "x-mitre-asset--1769c499-55e5-462f-bab2-c39b8cd5ae32"
    techniques_targeting_asset = mitre_attack_data.get_techniques_targeting_asset(asset_stix_id)

    print(f"Techniques targeting {asset_stix_id} ({len(techniques_targeting_asset)}):")
    for t in techniques_targeting_asset:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
