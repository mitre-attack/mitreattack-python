from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all techniques related to data components
    techniques_detected = mitre_attack_data.get_techniques_detected_by_datacomponents()
    print(f"Techniques detected by data components ({len(techniques_detected.keys())} data components):")
    for id, techniques in techniques_detected.items():
        print(f"* {id} - detects {len(techniques)} {'technique' if len(techniques) == 1 else 'techniques'}")

    # get techniques detected by Certificate: Certificate Registration
    techniques_detected_by_certificate = techniques_detected['x-mitre-data-component--1dad5aa4-4bb5-45e4-9e42-55d40003cfa6']
    print(f"\nTechniques detected by Certificate (DS0037): Certificate Registration ({len(techniques_detected_by_certificate)}):")
    for t in techniques_detected_by_certificate:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
