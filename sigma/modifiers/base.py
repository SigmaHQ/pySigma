class SigmaModifierBase(object):
    identifier : str = "base"
    active : bool = False

    def apply(self):
        raise SigmaNotImplementedError("Invalid attempt to apply base value modifier.")
