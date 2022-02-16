# pySigma

![Tests](https://github.com/SigmaHQ/pySigma/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/11b31b4f709b6dc54a30d5203e8fe0ee/raw/SigmaHQ-pySigma-coverage.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

`pySigma` is a python library that parses and converts Sigma rules into queries. It is a replacement
for the legacy Sigma toolchain (sigmac) with a much cleaner design and is almost fully tested.
Backends for support of conversion into query languages and processing pipelines for transforming
rule for log data models are separated into dedicated projects to keep pySigma itself slim and
vendor-agnostic. See the *Related Projects* section below to get an overview.

## Getting Started

To start using `pySigma`, install it using your python package manager of choice. Examples:

```
pip install pysigma
pipenv install pysigma
poetry add pysigma
```

Documentation with some usage examples can be found [here](https://sigmahq-pysigma.readthedocs.io/).

## Features

`pySigma` brings a number of additional features compared to `sigmac`, as well as some changes.

### Modifier comparison between pySigma and sigmac

|Modifier|Use|sigmac legacy|
|--------|---|:-------------:|
|contains|the value is matched anywhere in the field (strings and regular expressions)|X|
|startswith|The value is expected at the beginning of the field's content (strings and regular expressions)|X|
|endswith|The value is expected at the end of the field's content (strings and regular expressions)|X|
|base64|The value is encoded with Base64|X|
|base64offset|If a value might appear somewhere in a base64-encoded value the representation might change depending on the position in the overall value|X|
|wide|transforms value to UTF16-LE encoding|X|
|re|value is handled as regular expression by backends|X|
|cidr|value is handled as a IP CIDR by backends||
|all|This modifier changes OR logic to AND|X|
|lt|Field is less than the value||
|lte|Field is less or egal than the value||
|gt|Field is Greater than the value||
|gte|Field is Greater or egal than the value||
|expand|Modifier for expansion of placeholders in values. It replaces placeholder strings (%something%)||

## Overview

Conversion Overview

![Conversion Graph](/docs/images/conversion.png)

Pipelines

![Conversion Graph](/docs/images/pipelines.png)

More details are described in [the documentation](https://sigmahq-pysigma.readthedocs.io/).

## Testing

pySigma uses pytest as testing framework. Simply run `pytest` to run all tests. Run `pytest
--cov=sigma` to get a coverage report.

## Building

To build your own package run `poetry build`.

## Contributing

Pull requests are welcome. Please feel free to lodge any issues/PRs as discussion points.

## Maintainers

The project is currently maintained by:

- Thomas Patzke <thomas@patzke.org>
- [frack113](https://github.com/frack113)

## Related Projects

pySigma isn't a monolithic library attempting to support everything but the core. Support for target
query languages and log data models is provided by additional packages that extend pySigma:

* [sigma-cli](https://github.com/SigmaHQ/sigma-cli): a command line interface for conversion of
  Sigma rules based on pySigma. (work in progress, not yet on PyPI)
* [pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk):
* [pySigma-pipeline-sysmon](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
* [pySigma-pipeline-crowdstrike](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike)

All packages can also be installed from PyPI if not mentioned otherwise by the Python package
manager of your choice.

## License

GNU Lesser General Public License v2.1. For details, please see the full license file [located here](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE).
