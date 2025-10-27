from mitreattack.attackToExcel import attackToExcel
from stix2 import MemoryStore
import os

def main():
    # List of domains and version to process
    domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    output_dir = "output/"

    # Path to the STIX bundles for each domain (assumes STIX files are downloaded)
    stix_base_dir = os.environ.get("STIX_BASE_DIR", "attack-releases/stix-2.0/v17.1")
    stix_files = {
        "enterprise-attack": os.path.join(stix_base_dir, "enterprise-attack.json"),
        "mobile-attack": os.path.join(stix_base_dir, "mobile-attack.json"),
        "ics-attack": os.path.join(stix_base_dir, "ics-attack.json"),
    }

    for domain in domains:
        stix_file = stix_files[domain]
        print(f"Exporting {domain} to Excel...")

        # Load STIX data into MemoryStore
        mem_store = MemoryStore()
        mem_store.load_from_file(stix_file)

        # Export to Excel
        attackToExcel.export(
            domain=domain,
            output_dir=output_dir,
            mem_store=mem_store,
        )

if __name__ == "__main__":
    main()
