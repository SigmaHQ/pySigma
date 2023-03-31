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

## Autodiscovery and Migration of Backend Plugins

Recently, the backend plugin [autodiscovery](https://github.com/SigmaHQ/pySigma/blob/800c3e1be3670bab39767fd19d6d7fdd3effb8e6/sigma/plugins.py#L61) functionality has been added, eliminating the need for manual registration of plugins in [sigma-cli](https://github.com/SigmaHQ/sigma-cli). However, some backends may not function with the updated sigma-cli version. To address this issue, plugin developers should make the following changes to their backends:

1. In the `sigma/backends/my_awesome_backend/__init__.py` file, add a `backends` global variable that references the backend class:

    ```python
    from .my_awesome_backend import MyAwesomeBackend

    backends = {
        "my_awesome_backend": MyAwesomeBackend,
    }
    ```

2. In the `sigma/pipelines/my_awesome_pipelines/__init__.py` file, add a `pipelines` global variable that lists the available pipelines:

    ```python
    from .my_awesome_pipelines import pipeline_1, pipeline_2

    pipelines = {
        "pipeline_1": pipeline_1,
        "pipeline_2": pipeline_2,
    }
    ```

3. Finally, submit a pull request to the [pySigma-plugin-directory](https://github.com/SigmaHQ/pySigma-plugin-directory/blob/main/pySigma-plugins-v1.json) and update the version compatibility of your backend plugin with pySigma.

By following these steps, your backend plugin will be compatible with newer versions of pySigma and sigma-cli, allowing for autodiscovery and migration of backend plugins.

## Create Your Own Backend for pySigma

The creation of a backend has become much easier with pySigma. We recommend using the "Cookie Cutter Template" and reviewing the existing backends listed in the "Related Projects" section of this README.

[pySigma Cookie Cutter Template](https://github.com/SigmaHQ/cookiecutter-pySigma-backend)

## Features

`pySigma` brings a number of additional features compared to `sigmac`, as well as some changes.

### Modifier comparison between pySigma and sigmac

|Modifier|Use|sigmac legacy|
|--------|---|:-------------:|
|contains|the value is matched anywhere in the field (strings and regular expressions)|X|
|startswith|The value is expected at the beginning of the field's content (strings and regular expressions)|X|
|endswith|The value is expected at the end of the field's content (strings and regular expressions)|X|
|exists|The field exists (yes/true) in the matched event or doesn't exist (no/false)||
|base64|The value is encoded with Base64|X|
|base64offset|If a value might appear somewhere in a base64-encoded value the representation might change depending on the position in the overall value|X|
|wide|transforms value to UTF16-LE encoding|X|
|re|value is handled as regular expression by backends|X|
|i|Regular expression ignore case modifier||
|ignorecase|Regular expression ignore case modifier||
|m|Regular expression multiline modifier||
|multiline|Regular expression multiline modifier||
|s|Regular expression dot matches all modifier||
|dotall|Regular expression dot matches all modifier||
|cidr|value is handled as an IPv4 CIDR by backends ||
|all|This modifier changes OR logic to AND|X|
|lt|Field is less than the value||
|lte|Field is less or egal than the value||
|gt|Field is Greater than the value||
|gte|Field is Greater or egal than the value||
|expand|Modifier for expansion of placeholders in values. It replaces placeholder strings (%something%)||

### Backends comparison between pySigma and sigmac
On 2022/04/10
|sigmac Backends|Observation|pySigma|
|---------------|-----------|:-----:|
|ala |Azure Log Analytics Queries||
|ala-rule|Azure Log Analytics Rule||
|arcsight|ArcSight saved search||
|arcsight-esm|ArcSight ESM saved search||
|athena|SQL query||
|carbonblack|Converts Sigma rule into CarbonBlack query string|
|chronicle|Google Chronicle YARA-L|
|crowdstrike|CrowdStrike Search Processing Language (SPL)|[pySigma-pipeline-crowdstrike](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike)|
|csharp|CSharp Regex in LINQ query|
|datadog-logs|Datadog log search query|
|devo|Devo query|
|ee-outliers|ee-outliers|
|elastalert|ElastAlert QS query|
|elastalert-dsl|ElastAlert DSL query|
|es-dsl|Elasticsearch DSL query|[pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)|
|es-eql|Elasticsearch EQL query|
|es-qs|Elasticsearch query string. Only searches, no aggregations|[pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)|
| es-qs-lr|Lucene query string for LogRhythm. Only searches, no aggregations|
|es-rule|Elastic SIEM lucene query|
|es-rule-eql|Elastic SIEM EQL query|
|fieldlist|List all fieldnames from given Sigma rules for creation of a field mapping configuration|
|fireeye-helix|FireEye Helix Query Language|
|fortisiem|Base class for Fortisem backends that generate one text-based expression from a Sigma rule|
|graylog|Graylog query string. Only searches, no aggregations|
|grep|Generates Perl compatible regular expressions and puts 'grep -P' around it|
|hawk|HAWK search|
|humio|Humio query|
|kibana|Kibana JSON Configuration files (searches only)|
|kibana-ndjson|Kibana JSON Configuration files (searches only)|[pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)|
|lacework|Lacework Policy Platform|
|limacharlie|LimaCharlie D&R rules|
|logiq|LOGIQ event rule api payload|
|logpoint|LogPoint query|
|mdatp|Microsoft Defender ATP Hunting Queries|[pySigma-backend-microsoft365defender](https://github.com/AttackIQ/pySigma-backend-microsoft365defender)|
|netwitness|NetWitness saved search|
|netwitness-epl|RSA NetWitness EPL|
|es-qs (proxied)|OpenSearch search query string. Only searches, no aggregations|[pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch) (proxied by [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)) |
|es-dsl (proxied)|OpenSearch DSL query|[pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch) (proxied by [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)) |
|opensearch-monitor|OpenSearch monitors and ElasticRule are in Elastic Common Schema|[pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch)|
|powershell|PowerShell event log cmdlets|
|qradar|Qradar saved search|
|qualys|Qualys saved search|
|sentinel-rule|Azure Sentinel scheduled alert rule ARM template|
|splunk|Splunk Search Processing Language (SPL)|[pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk)|
|splunkdm|Splunk syntax leveraging Datamodel acceleration|
|splunkxml|XML used for Splunk Dashboard Panels|
|sql|SQL query|
|sqlite|SQL query for SQLite|
|stix|STIX pattern|
|sumologic|SumoLogic query|
|sumologic-cse|SumoLogic CSE query|
|sumologic-cse-rule|SumoLogic CSE query|
|sysmon|sysmon XML configuration|
|uberagent|uberAgent ESA's process tagging rules|
|xpack-watcher|X-Pack Watcher JSON for alerting|

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

This [blog post](https://medium.com/@micahbabinski/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142) by Micah Babinski explains the process from a developer's perspective.

## Maintainers

The project is currently maintained by:

- Thomas Patzke <thomas@patzke.org>
- [frack113](https://github.com/frack113)

## Related Projects

pySigma isn't a monolithic library attempting to support everything but the core. Support for target
query languages and log data models is provided by additional packages that extend pySigma:

* [sigma-cli](https://github.com/SigmaHQ/sigma-cli): a command line interface for conversion of
  Sigma rules based on pySigma.
* [pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk)
* [pySigma-pipeline-sysmon](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
* [pySigma-pipeline-crowdstrike](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike)

All packages can also be installed from PyPI if not mentioned otherwise by the Python package
manager of your choice.

## License

GNU Lesser General Public License v2.1. For details, please see the full license file [located here](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE).
