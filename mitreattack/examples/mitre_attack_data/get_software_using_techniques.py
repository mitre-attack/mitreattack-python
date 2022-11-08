from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all software related to techniques
    software_using_techniques = mitre_attack_data.get_software_using_techniques()
    print(f"Software using techniques ({len(software_using_techniques.keys())} techniques):")
    for id, software in software_using_techniques.items():
        print(f"* {id} - used by {len(software)} software")

    # get software related to T1014
    software_using_t1014 = software_using_techniques['attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b']
    print(f"\nSoftware using T1014 ({len(software_using_t1014)}):")
    for s in software_using_t1014:
        software = s['object']
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
