import json
from sys import stderr, stdout
from pprint import pformat
from typing import Optional, Dict


from sigma.data.mitre_attack import mitre_attack_version
import requests


class MitreAttackData:
    modified: str = "2018-01-17T12:56:55.080Z"
    attack_version: str = "1.0"
    url_info: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/index.json"
    )
    url_enterprise: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/enterprise-attack/enterprise-attack.json"
    )
    url_mobile: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/mobile-attack/mobile-attack.json"
    )
    url_ics: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/ics-attack/ics-attack.json"
    )
    data_enterprise: Optional[Dict] = None
    data_mobile: Optional[Dict] = None
    data_ics: Optional[Dict] = None

    def fetch_attack_stix_json(self, url: str) -> Optional[Dict]:
        print(f"Proceed : {url}")
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None

    def update_data(self):
        self.data_enterprise = self.fetch_attack_stix_json(self.url_enterprise)
        self.data_mobile = self.fetch_attack_stix_json(self.url_mobile)
        self.data_ics = self.fetch_attack_stix_json(self.url_ics)

    def get_last_version(self) -> Optional[str]:
        try:
            response = requests.get(self.url_info, timeout=20)
            response.raise_for_status()
            data = response.json()
            self.modified = data.get("modified", self.modified)
            collections = data.get("collections", [])
            for collection in collections:
                versions = collection.get("versions", [])
                for version in versions:
                    if version.get("modified") == self.modified:
                        self.attack_version = version.get("version", self.attack_version)
                        return self.attack_version
            return None
        except Exception:
            return None

    def generate_attack_content(self, filename):
        def get_attack_id(refs):
            for ref in refs:  # Iterate over all references, one contains identifier
                src = ref.get("source_name", "")
                if src.startswith("mitre") and src.endswith("attack"):
                    return ref["external_id"]

        tactics = dict()
        techniques = dict()
        techniques_tactics_mapping = dict()
        intrusion_sets = dict()
        software = dict()

        if self.data_enterprise is None or self.data_mobile is None or self.data_ics is None:
            return

        for stix in [self.data_enterprise, self.data_mobile, self.data_ics]:
            for obj in stix["objects"]:  # iterate over all STIX objects
                if not (
                    obj.get("revoked") or obj.get("x_mitre_deprecated")
                ):  # ignore deprecated items
                    if (obj_type := obj.get("type")) is not None:
                        if obj_type == "x-mitre-tactic":  # Tactic
                            tactic_id = get_attack_id(obj["external_references"])
                            tactics[tactic_id] = obj["x_mitre_shortname"]
                        elif obj_type == "attack-pattern":  # Technique
                            technique_id = get_attack_id(obj["external_references"])
                            techniques[technique_id] = obj["name"]
                            techniques_tactics_mapping[technique_id] = [
                                phase["phase_name"]
                                for phase in obj["kill_chain_phases"]
                                if phase["kill_chain_name"] == "mitre-attack"
                            ]
                        elif obj_type == "intrusion-set":
                            intrusion_set_id = get_attack_id(obj["external_references"])
                            intrusion_sets[intrusion_set_id] = obj["name"]
                        elif obj_type in ("malware", "tool"):
                            software_id = get_attack_id(obj["external_references"])
                            software[software_id] = obj["name"]
                        elif obj_type == "x-mitre-collection":
                            attack_version = obj["x_mitre_version"]

        with open(filename, "w", encoding="UTF-8", newline="") as fileouput:
            print(
                f"Found {len(tactics)} tactics, {len(techniques)} techniques ({len(techniques_tactics_mapping)} mapped to tactics), {len(intrusion_sets)} intrusion sets and {len(software)} malwares.",
                file=stderr,
            )
            print("from typing import Dict, List", file=fileouput)
            print(f'mitre_attack_version: str = "{self.attack_version}"', file=fileouput)
            print(
                "mitre_attack_tactics: Dict[str, str] = "
                + pformat(tactics, indent=4, sort_dicts=True),
                file=fileouput,
            )
            print(
                "mitre_attack_techniques: Dict[str, str] = "
                + pformat(techniques, indent=4, sort_dicts=True),
                file=fileouput,
            )
            print(
                "mitre_attack_techniques_tactics_mapping: Dict[str, List[str]] = "
                + pformat(techniques_tactics_mapping, indent=4, sort_dicts=True),
                file=fileouput,
            )
            print(
                "mitre_attack_intrusion_sets: Dict[str, str] = "
                + pformat(intrusion_sets, indent=4, sort_dicts=True),
                file=fileouput,
            )
            print(
                "mitre_attack_software: Dict[str, str] = "
                + pformat(software, indent=4, sort_dicts=True),
                file=fileouput,
            )


if __name__ == "__main__":
    print("Generate MITRE ATT&CK(r) content for pySigma from ATT&CK STIX definition.")
    print(f"Actual Mitre Attack version : {mitre_attack_version}")
    attackdata = MitreAttackData()
    attackversion = attackdata.get_last_version()
    if attackversion and not attackversion == mitre_attack_version:
        print(f"Update Mitre Attack data to : {attackversion}")
        attackdata.update_data()
        attackdata.generate_attack_content("./sigma/data/mitre_attack.py")
