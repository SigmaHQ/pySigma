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

## Create Your Own Backend for pySigma

The creation of a backend has become much easier with pySigma. We recommend using the "Cookie Cutter Template" and reviewing the existing backends listed in the "Related Projects" section of this README.

[pySigma Cookie Cutter Template](https://github.com/SigmaHQ/cookiecutter-pySigma-backend)

## Features

`pySigma` brings a number of additional features compared to the all in one `sigmac`, as well as some changes.

[sigma-cli](https://github.com/SigmaHQ/sigma-cli) is the equivalent of sigmac for command-line conversion

### Modifier 

use `sigma list modifiers`

### Backends

use `sigma plugin list --plugin-type backend`

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

## Linting

To lint the code run `poetry run black`. To check for linting errors run `poetry run black --check`.

This project also uses [pre-commit](https://pre-commit.com/), which is installed by poetry as part of dev dependencies. To install the git hooks run `poetry run pre-commit install` after cloning the repository and installing the dependencies.

## Contributing

Pull requests are welcome. Please feel free to lodge any issues/PRs as discussion points.

This [blog post](https://medium.com/@micahbabinski/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142) by Micah Babinski explains the process from a developer's perspective.

## Maintainers

The project is currently maintained by:

- Thomas Patzke <thomas@patzke.org>
- [François Hubaut](https://github.com/frack113)

## Related Projects

pySigma isn't a monolithic library attempting to support everything but the core. Support for target
query languages and log data models is provided by additional packages that extend pySigma:

* [sigma-cli](https://github.com/SigmaHQ/sigma-cli): a command line interface for conversion of
  Sigma rules based on pySigma.
* [pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk)
* [pySigma-pipeline-sysmon](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
* [pySigma-pipeline-crowdstrike](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike)
* [pySigma-backend-netwitness](https://github.com/marcelkwaschny/pySigma-backend-netwitness)

All packages can also be installed from PyPI if not mentioned otherwise by the Python package
manager of your choice.

## License

GNU Lesser General Public License v2.1. For details, please see the full license file [located here](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE).
