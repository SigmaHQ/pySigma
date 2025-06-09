import json
from sys import stderr, stdout
from pprint import pformat
from typing import Optional, Dict, List, Union
from pathlib import Path
from dataclasses import dataclass

from sigma.data.mitre_attack import mitre_attack_version
import requests


@dataclass
class MitreAttackUrls:
    info: str = "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/index.json"
    enterprise: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/enterprise-attack/enterprise-attack.json"
    )
    mobile: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/mobile-attack/mobile-attack.json"
    )
    ics: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/ics-attack/ics-attack.json"
    )


class MitreAttackData:
    MITRE_ATTACK_KEY = "mitre-attack"
    DEFAULT_TIMEOUT = 20
    DEFAULT_MODIFIED = "2018-01-17T12:56:55.080Z"

    def __init__(self):
        self.modified = self.DEFAULT_MODIFIED
        self.attack_version: Optional[str] = None
        self.urls = MitreAttackUrls()
        self.data_enterprise: Optional[Dict] = None
        self.data_mobile: Optional[Dict] = None
        self.data_ics: Optional[Dict] = None
        self.check_enterprise: bool = True
        self.check_mobile: bool = False
        self.check_ics: bool = False
        self.tactics: Dict[str, str] = dict()
        self.techniques: Dict[str, str] = dict()
        self.techniques_tactics_mapping = dict()
        self.intrusion_sets = dict()
        self.software = dict()

    def fetch_attack_stix_json(self, url: str) -> Optional[Dict]:
        try:
            response = requests.get(url, timeout=self.DEFAULT_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching data: {e}", file=stderr)
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}", file=stderr)
            return None

    def update_data(self):
        if self.check_enterprise:
            self.data_enterprise = self.fetch_attack_stix_json(self.urls.enterprise)
        if self.check_mobile:
            self.data_mobile = self.fetch_attack_stix_json(self.urls.mobile)
        if self.check_ics:
            self.data_ics = self.fetch_attack_stix_json(self.urls.ics)

    def get_last_version(self) -> Optional[str]:
        try:
            response = requests.get(self.urls.info, timeout=self.DEFAULT_TIMEOUT)
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

    def extract_information(self, stix: Dict, key_name: str = MITRE_ATTACK_KEY) -> None:
        """Extract MITRE ATT&CK information from STIX data.

        Args:
            stix: Dictionary containing STIX objects
            key_name: Name of the kill chain (e.g. 'mitre-attack')
        """

        def get_attack_id(refs):
            for ref in refs:  # Iterate over all references, one contains identifier
                src = ref.get("source_name", "")
                if src.startswith("mitre") and src.endswith("attack"):
                    return ref["external_id"]

        for obj in stix["objects"]:  # iterate over all STIX objects
            if not (obj.get("revoked") or obj.get("x_mitre_deprecated")):  # ignore deprecated items
                if (obj_type := obj.get("type")) is not None:
                    if obj_type == "x-mitre-tactic":  # Tactic
                        tactic_id = get_attack_id(obj["external_references"])
                        if tactic_id:
                            self.tactics[tactic_id] = obj["x_mitre_shortname"]
                    elif obj_type == "attack-pattern":  # Technique
                        technique_id = get_attack_id(obj["external_references"])
                        if technique_id:
                            self.techniques[technique_id] = obj["name"]
                            self.techniques_tactics_mapping[technique_id] = [
                                phase["phase_name"]
                                for phase in obj["kill_chain_phases"]
                                if phase["kill_chain_name"] == key_name
                            ]
                    elif obj_type == "intrusion-set":
                        intrusion_set_id = get_attack_id(obj["external_references"])
                        if intrusion_set_id:
                            self.intrusion_sets[intrusion_set_id] = obj["name"]
                    elif obj_type in ("malware", "tool"):
                        software_id = get_attack_id(obj["external_references"])
                        if software_id:
                            self.software[software_id] = obj["name"]
                    elif obj_type == "x-mitre-collection":
                        self.attack_version = obj["x_mitre_version"]

    def generate_attack_content(self, filename: Union[str, Path]):
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open("w", encoding="UTF-8", newline="") as fileoutput:
            if self.data_enterprise is not None:
                self.extract_information(self.data_enterprise, "mitre-attack")

            print(
                f"Found {len(self.tactics)} tactics, {len(self.techniques)} techniques ({len(self.techniques_tactics_mapping)} mapped to tactics), {len(self.intrusion_sets)} intrusion sets and {len(self.software)} malwares.",
                file=stderr,
            )
            print("from typing import Dict, List", file=fileoutput)
            print(f'mitre_attack_version: str = "{self.attack_version}"', file=fileoutput)
            print(
                "mitre_attack_tactics: Dict[str, str] = "
                + pformat(self.tactics, indent=4, sort_dicts=True),
                file=fileoutput,
            )
            print(
                "mitre_attack_techniques: Dict[str, str] = "
                + pformat(self.techniques, indent=4, sort_dicts=True),
                file=fileoutput,
            )
            print(
                "mitre_attack_techniques_tactics_mapping: Dict[str, List[str]] = "
                + pformat(self.techniques_tactics_mapping, indent=4, sort_dicts=True),
                file=fileoutput,
            )
            print(
                "mitre_attack_intrusion_sets: Dict[str, str] = "
                + pformat(self.intrusion_sets, indent=4, sort_dicts=True),
                file=fileoutput,
            )
            print(
                "mitre_attack_software: Dict[str, str] = "
                + pformat(self.software, indent=4, sort_dicts=True),
                file=fileoutput,
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
        print(f"Use black before making a PR")
