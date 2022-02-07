# pySigma

![Tests](https://github.com/SigmaHQ/pySigma/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/11b31b4f709b6dc54a30d5203e8fe0ee/raw/SigmaHQ-pySigma-coverage.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

`pySigma` is a python library that parses and converts Sigma rules into queries.

It replaces a lot of the logic found in the `sigmac` tool, and brings it into a modern Python library. For a CLI version of the new Sigma tool, see (TBA).

## Getting Started

To start using `pySigma`, install it using your python package manager of choice. Documentation with
some usage examples can be found [here](https://sigmahq-pysigma.readthedocs.io/).

**Poetry:**

```bash
poetry add git+https://github.com/SigmaHQ/pySigma.git#main
```

**Pipenv:**

```bash
pipenv install git+https://github.com/SigmaHQ/pySigma.git#egg=pysigma
```

## Features

`pySigma` brings a number of additional features over `sigmac`, as well as some changes.

### Modifier compare from sigmac

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

To run the pytest suite for `pySigma`, run the following command:

```bash
make test
```

## Contributing

Pull requests are welcome. Please feel free to lodge any issues/PRs as discussion points.

## Authors

- Thomas Patzke <thomas@patzke.org>

## Licence

GNU Lesser General Public License v2.1. For details, please see the full license file [located here](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE).
