import argparse
from argparse import ArgumentParser
from pathlib import Path

from typing import List, Optional, IO
from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.conversion.backends.splunk import SplunkBackend
from sigma.conversion.base import TextQueryBackend

backends = {    # identifier -> backend class, description, mandatory processing pipeline
    "splunk": (SplunkBackend, "Splunk Search Processing Language (SPL)", True),
}

class SigmaConverterArgumentParser(ArgumentParser):
    def convert_arg_line_to_args(self, arg_line: str) -> List[str]:
        return arg_line.split()

    def list_backends(self, file: Optional[IO[str]] = None):
        longest_id = max((
            len(key)
            for key in backends.keys()
        ))
        print("\nBackends:", file=file)
        for key, val in backends.items():
            print(f"{key:<{ longest_id }} | {val[1]}", file=file)

    def print_help(self, file: Optional[IO[str]] = None) -> None:
        super().print_help(file=file)
        self.list_backends(file)

def resolve_files(filespecs : List[str], file_pattern : str) -> List[Path]:
    """
    Resolve mixed files and directories to list of pathlib Path objects. Directories are
    traversed recursively and all files matching the file-pattern argument are used.
    """
    return [
        (item, SigmaCollection.from_yaml(item.open().read()))
        for sublist in [
            path.glob(f"**/{ file_pattern }")
            if path.is_dir()
            else [ path ]
            for path in (
                Path(rule)
                for rule in filespecs
            )
        ]
        for item in sublist
    ]

def convert(args):
    sigma_rules = resolve_files(args.file, args.file_pattern)
    pipeline = ProcessingPipelineResolver().resolve(args.config)
    backend_class = backends[args.backend][0]
    backend : TextQueryBackend = backend_class(pipeline)
    for path, sigma_rule in sigma_rules:
        print(f"=== Sigma Rule: { path } ===")
        print("\n".join(backend.convert(sigma_rule)))

def main():
    argparser = SigmaConverterArgumentParser(
        description="Convert Sigma rules to queries",
        fromfile_prefix_chars="@",
    )
    argparser.add_argument("--backend", "-b", choices=backends.keys(), help="Conversion backend")
    argparser.add_argument("--config", "-c", action="append", default=[], help="Processing pipeline configuration files. Mandatory for some backends.")
    argparser.add_argument("--file-pattern", "-P", default="*.yml", help="File pattern that must match for traversal of directories. (default: %(default)s)")
    argparser.add_argument("file", nargs="+", help="Sigma rules or directories containing Sigma rules.")
    args = argparser.parse_args()

    convert(args)