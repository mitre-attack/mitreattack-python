from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("ics-attack.json")

    # get assets targeted by T0806
    technique_stix_id = "attack-pattern--8e7089d3-fba2-44f8-94a8-9a79c53920c4"
    assets_targeted = mitre_attack_data.get_assets_targeted_by_technique(technique_stix_id)

    print(f"Assets targeted by {technique_stix_id} ({len(assets_targeted)}):")
    for a in assets_targeted:
        asset = a["object"]
        print(f"* {asset.name} ({mitre_attack_data.get_attack_id(asset.id)})")


if __name__ == "__main__":
    main()
