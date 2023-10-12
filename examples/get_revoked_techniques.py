from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    techniques = mitre_attack_data.get_techniques()

    for technique in techniques:
        if technique.get("revoked"):
            stix_id = technique["id"]
            revoked_technique_attack_id = mitre_attack_data.get_attack_id(stix_id=technique["id"])
            revoked_technique_name = technique["name"]

            revoking_object = mitre_attack_data.get_revoking_object(revoked_stix_id=stix_id)
            revoking_object_name = revoking_object.get("name")
            revoking_object_attack_id = mitre_attack_data.get_attack_id(stix_id=revoking_object["id"])
            print(
                f"[{revoked_technique_attack_id}] {revoked_technique_name} was revoked by [{revoking_object_attack_id}] {revoking_object_name}"
            )


if __name__ == "__main__":
    main()
