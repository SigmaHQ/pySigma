# sigmatools

![Tests](https://github.com/SigmaHQ/sigmatools/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/11b31b4f709b6dc54a30d5203e8fe0ee/raw/SigmaHQ-sigmatools-coverage.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

`sigmatools` is a python library that parses and converts Sigma rules into queries. 

It replaces a lot of the logic found in the `sigmac` tool, and brings it into a modern Python library. For a CLI version of the new Sigma tool, see (TBA).  

## Getting Started

To start using `sigmatools`, install it using your python package manager of choice.

**Poetry:**

```bash
poetry add git+https://github.com/SigmaHQ/sigmatools.git#main
```

**Pipenv:**

```bash
pipenv install git+https://github.com/SigmaHQ/sigmatools.git#main
```

## Features

`sigmatools` brings a number of additional features over `sigmac`, as well as some changes.

### Rule Inclusions

Rules can now include other rules using the `action: include` directive. An example is shown below.

```yaml
action: include
filename: include-1.yml
```

## Testing

To run the pytest suite for `sigmatools`, run the following command:

```bash
make test
```

## Contributing

Pull requests are welcome. Please feel free to lodge any issues/PRs as discussion points.
 
## Authors

- Thomas Patzke <thomas@patzke.org>

## Licence

GNU Lesser General Public License v2.1. For details, please see the full license file [located here](https://github.com/SigmaHQ/sigmatools/blob/main/LICENSE).
