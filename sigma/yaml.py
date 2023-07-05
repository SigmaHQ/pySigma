try:
    import ryaml
    import yaml
    using_ryaml = True
except ImportError:
    import yaml
    using_ryaml = False

    class SigmaYAMLLoader(yaml.SafeLoader):
        """Custom YAML loader implementing additional functionality for Sigma."""
        def construct_mapping(self, node, deep=...):
            keys = set()
            for k, v in node.value:
                key = self.construct_object(k, deep=deep)
                if key in keys:
                    raise yaml.error.YAMLError("Duplicate key '{k}'")
                else:
                    keys.add(key)
            return super().construct_mapping(node, deep)


def safe_load_all(yaml_str):
    if not using_ryaml:
        return yaml.safe_load_all(yaml_str)
    if isinstance(yaml_str, str):
        return ryaml.loads_all(yaml_str)
    return ryaml.load_all(yaml_str)


def load(yaml_str):
    if not using_ryaml:
        return yaml.load(yaml_str, SigmaYAMLLoader)

    if isinstance(yaml_str, str):
        result = ryaml.loads(yaml_str)
    else:
        result = ryaml.load(yaml_str)

    # TODO validate keys here.
    return result


def safe_load(yaml_str):
    if not using_ryaml:
        return yaml.safe_load(yaml_str)
    if isinstance(yaml_str, str):
        result = ryaml.loads(yaml_str)
    else:
        result = ryaml.load(yaml_str)
    return result
