from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get software related to T1014
    technique_stix_id = "attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b"
    software_using_t1014 = mitre_attack_data.get_software_using_technique(technique_stix_id)

    print(f"Software using T1014 ({len(software_using_t1014)}):")
    for s in software_using_t1014:
        software = s["object"]
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
