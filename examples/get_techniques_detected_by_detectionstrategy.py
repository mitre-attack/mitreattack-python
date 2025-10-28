import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get technique detected by detection strategy
    detectionstrategy_stix_id = "x-mitre-detection-strategy--00060b87-7f99-45aa-9553-a4d94139195c"
    techniques_detected_by_det = mitre_attack_data.get_techniques_detected_by_detection_strategy(
        detectionstrategy_stix_id
    )

    print("Techniques detected by DET0103:")
    for t in techniques_detected_by_det:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
