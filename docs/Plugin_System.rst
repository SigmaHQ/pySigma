Plugin System
#############

pySigma implements a plugin architecture that decouples the development of the following entities
from the core pySigma library:

* :doc:`/Backends`
* :doc:`/Processing_Pipelines`
* :doc:`Rule Validators </Rule_Validation>`

The plugin system resides in the :mod:`sigma.plugins` module and takes care of providing information
about available plugins as well as their installation with the
:class:`sigma.plugins.SigmaPluginDirectory` class. The :class:`sigma.plugins.InstalledSigmaPlugins`
discovers classes provided by plugins and allows the usage via defined identifiers if the plugin
modules follow certain conventions.

Implementing Plugins
********************

Each module that wants to be recognized as pySigma plugin must provide a mapping between identifiers
and their respecitve definitions in their module. Plugins are generally implemented as `namespace
packages <https://packaging.python.org/en/latest/guides/packaging-namespace-packages/>`_ with
following conventions:

* Backends reside as module in the namespace package :mod:`sigma.backends` and provide a dict
  `backends` with the mapping between identifiers and backend classes.
* Processing pipelines reside as module in the namespace package :mod:`sigma.pipelines` and provide
  a dict `pipelines` with the mapping between identifiers and a function that returns a
  :class:`sigma.processing.pipeline.ProcessingPipeline` object.
* Rule validators reside in the namespace package :mod:`sigma.validators` and provide a dict
  `validators` with the mapping between identifiers and rule validator classes.

THe most straightforward way is to import all classes that should be available as plugin class in
the :file:`__init__.py` of the module and add them to the mappings mentioned above.

Discover Available Plugins
**************************

tbd

Discover Installed Plugins
**************************

tbd