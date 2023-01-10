from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get techniques detected by Certificate: Certificate Registration
    datacomponent_stix_id = "x-mitre-data-component--1dad5aa4-4bb5-45e4-9e42-55d40003cfa6"
    techniques_detected_by_certificate = mitre_attack_data.get_techniques_detected_by_datacomponent(
        datacomponent_stix_id
    )

    print(
        f"Techniques detected by Certificate (DS0037): Certificate Registration ({len(techniques_detected_by_certificate)}):"
    )
    for t in techniques_detected_by_certificate:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
