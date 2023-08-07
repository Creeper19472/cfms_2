import pluggy

hook_spec = pluggy.HookspecMarker("cfms")


class PluginSpec(object):
    """A hook specification namespace."""
    @hook_spec
    def version(self):
        """
        Should return the version of the specified plugin.
        """

