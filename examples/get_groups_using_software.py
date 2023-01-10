from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get groups related to S0349
    software_stix_id = "tool--b76b2d94-60e4-4107-a903-4a3a7622fb3b"
    groups_using_s0349 = mitre_attack_data.get_groups_using_software(software_stix_id)

    print(f"Groups using S0349 ({len(groups_using_s0349)}):")
    for g in groups_using_s0349:
        group = g["object"]
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
