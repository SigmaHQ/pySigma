from argparse import ArgumentParser, FileType
import json
from sys import stderr, stdout
from pprint import pformat

argparser = ArgumentParser(description="Generate MITRE ATT&CK(r) content for pySigma from ATT&CK STIX definition.")
argparser.add_argument("--output", "-o", type=FileType("wt", encoding="utf-8"), default=stdout, help="Output file")
argparser.add_argument('--attack_version', type=str, default="12.1", help='Manually set the MITRE ATT&CK(r) version.')
argparser.add_argument("stix", type=FileType("r"), nargs="+", help="Files with ATT&CK STIX definitions")
args = argparser.parse_args()

def get_attack_id(refs):
        for ref in refs:                  # Iterate over all references, one contains identifier
            src = ref.get("source_name", "")
            if src.startswith("mitre") and src.endswith("attack"):
                return ref["external_id"]

tactics = dict()
techniques = dict()
techniques_tactics_mapping = dict()
intrusion_sets = dict()
software = dict()
for stix_file in args.stix:
    stix = json.load(stix_file)
    for obj in stix["objects"]:     # iterate over all STIX objects
        if not (obj.get("revoked") or obj.get("x_mitre_deprecated")):       # ignore deprecated items
            if (obj_type := obj.get("type")) is not None:
                if obj_type == "x-mitre-tactic":                            # Tactic
                    tactic_id = get_attack_id(obj["external_references"])
                    tactics[tactic_id] = obj["x_mitre_shortname"]
                elif obj_type == "attack-pattern":                          # Technique
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

if not 'attack_version' in locals():
    attack_version = args.attack_version
print(f"Found { len(tactics) } tactics, { len(techniques) } techniques ({ len(techniques_tactics_mapping) } mapped to tactics), { len(intrusion_sets) } intrusion sets and { len(software) } malwares.", file=stderr)
print("from typing import Dict, List", file=args.output)
print(f'mitre_attack_version: str = "{ attack_version }"', file=args.output)
print("mitre_attack_tactics: Dict[str, str] = " + pformat(tactics, indent=4, sort_dicts=True), file=args.output)
print("mitre_attack_techniques: Dict[str, str] = " + pformat(techniques, indent=4, sort_dicts=True), file=args.output)
print("mitre_attack_techniques_tactics_mapping: Dict[str, List[str]] = " + pformat(techniques_tactics_mapping, indent=4, sort_dicts=True), file=args.output)
print("mitre_attack_intrusion_sets: Dict[str, str] = " + pformat(intrusion_sets, indent=4, sort_dicts=True), file=args.output)
print("mitre_attack_software: Dict[str, str] = " + pformat(software, indent=4, sort_dicts=True), file=args.output)