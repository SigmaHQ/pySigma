import json
from sys import stderr
from pprint import pformat
from typing import Optional, Dict
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass
from sigma.data.mitre_attack import mitre_attack_version
import requests

from mitreattack.stix20 import MitreAttackData


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


class MyMitreAttackData:
    ENTERPRISE_URL: str = MitreAttackUrls.enterprise
    JSON_PATH: Path = Path("tools/enterprise-attack.json")
    PY_PATH: Path = Path("sigma/data/mitre_attack.py")
    DEFAULT_TIMEOUT = 20

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.remove_json()

    def __init__(self):
        self.attack_version: Optional[str] = None
        self.tactics: Dict[str, str] = dict()
        self.techniques: Dict[str, str] = dict()
        self.techniques_tactics_mapping: Dict[str, list] = dict()
        self.intrusion_sets: Dict[str, str] = dict()
        self.software: Dict[str, str] = dict()

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

    def download_json(self):
        enterprise_json = self.fetch_attack_stix_json(self.ENTERPRISE_URL)
        if enterprise_json:
            with self.JSON_PATH.open("w", encoding="utf-8") as f:
                json.dump(enterprise_json, f, indent=2)
            self.attack_version = next(
                (
                    x["x_mitre_version"]
                    for x in enterprise_json["objects"]
                    if x["type"] == "x-mitre-collection"
                ),
                None,
            )

    def update_mitre_information(self) -> None:
        """Update MITRE ATT&CK information from downloaded STIX data.

        Processes groups, tactics, techniques and software information
        from the STIX JSON file and updates internal dictionaries.
        """
        mitre_attack_data = MitreAttackData(str(self.JSON_PATH))
        groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
        print(f"Retrieved {len(groups)} ATT&CK groups.")
        for group in groups:
            group_id = next(
                (
                    x["external_id"]
                    for x in group.get("external_references")
                    if x["source_name"] == "mitre-attack"
                ),
                "Undef",
            )
            group_name = group.get("name")
            self.intrusion_sets[group_id] = group_name

        tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
        print(f"Retrieved {len(tactics)} ATT&CK tactics.")
        for tactic in tactics:
            tactic_id = tactic.get("external_references")[0].get("external_id")
            tactic_name = tactic.get("name")
            self.tactics[tactic_id] = tactic_name.lower().replace(" ", "-")

        techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
        print(f"Retrieved {len(techniques)} ATT&CK techniques.")
        for technique in techniques:
            technique_id = next(
                (
                    x["external_id"]
                    for x in technique.get("external_references")
                    if x["source_name"] == "mitre-attack"
                ),
                "Undef",
            )
            technique_name = technique.get("name")
            self.techniques[technique_id] = technique_name
            killChainPhase = [x.phase_name for x in technique.get("kill_chain_phases")]
            self.techniques_tactics_mapping[technique_id] = killChainPhase

        softwares = mitre_attack_data.get_software(remove_revoked_deprecated=True)
        print(f"Retrieved {len(softwares)} ATT&CK software.")
        for software in softwares:
            software_id = next(
                (
                    x["external_id"]
                    for x in software.get("external_references")
                    if x["source_name"] == "mitre-attack"
                ),
                "Undef",
            )
            software_name = software.get("name")
            self.software[software_id] = software_name

    def validate_url(self, url: str) -> bool:
        """Validate if the provided URL is well-formed."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def generate_attack_content(self) -> None:
        with self.PY_PATH.open("w", encoding="UTF-8", newline="") as fileoutput:
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

    def remove_json(self):
        if self.JSON_PATH.exists():
            self.JSON_PATH.unlink()


if __name__ == "__main__":
    print(
        "Generate MITRE ATT&CK(r) content for pySigma from enterprise-attack ATT&CK STIX definition."
    )
    print(f"Actual MITRE Attack version : {mitre_attack_version}")
    with MyMitreAttackData() as attackdata:
        attackdata.download_json()
        if attackdata.attack_version and not attackdata.attack_version == mitre_attack_version:
            print(f"Update MITRE Attack data to : {attackdata.attack_version}")
            attackdata.update_mitre_information()
            attackdata.generate_attack_content()
            print(f"Use black before making a PR for pySigma")
