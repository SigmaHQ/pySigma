.. py:currentmodule:: sigma.plugins

Plugin System
#############

pySigma implements a plugin architecture that decouples the development of the following entities
from the core pySigma library:

* :doc:`/Backends`
* :doc:`/Processing_Pipelines`
* :doc:`Rule Validators </Rule_Validation>`

The plugin system resides in the :mod:`sigma.plugins` module and takes care of providing information
about available plugins as well as their installation with the
:class:`SigmaPluginDirectory` class. The :class:`InstalledSigmaPlugins`
discovers classes provided by plugins and allows the usage via defined identifiers if the plugin
modules follow certain conventions.

Implementing Plugins
********************

.. _plugin-metadata:

Python Module
=============

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

The most straightforward way is to import all classes that should be available as plugin class in
the :file:`__init__.py` of the module and add them to the mappings mentioned above.

Plugin Directory
================

The `pySigma plugin directory <https://github.com/SigmaHQ/pySigma-plugin-directory>` is the central
list of public available plugins for installation. It's format is described in the `README file of
the project <https://github.com/SigmaHQ/pySigma-plugin-directory#format>`. The directory itself is
consumed by the `Sigma CLI <https://github.com/SigmaHQ/sigma-cli>` for discovery. Therefore, each
plugin that should be available for usage with the CLI must be added to the directory.

Discover Available Plugins
**************************

The :class:`SigmaPluginDirectory` class is an interface to the Sigma plugin directory.
The following code instantiates an object of this class with the current content of the plugin
directory::

    plugins = SigmaPluginDirectory.default_plugin_directory()

This class also allows to use alternative plugin directories with the
:meth:`sigma.plugins.SigmaPluginDirectory.from_url()` method.

A list of available plugins is then returned by this code::

    plugins.get_plugins(
        plugin_types={ SigmaPluginType.BACKEND },
        plugin_state={ SigmaPluginState.STABLE },
        compatible_only=True,
    )

This code returns all stable backends that are compatible with the used pySigma version as list of
:class:`SigmaPlugin` objects. Instances of these classes can be used to install a
plugin as follows::

    plugin.install()

.. autoclass:: sigma.plugins.SigmaPluginDirectory
   :members:

.. autoclass:: sigma.plugins.SigmaPlugin
   :members:

Discover Installed Plugins
**************************

The class :class:`InstalledSigmaPlugins` main purpose is the discovery of classes
provided by plugins. It is usually instantiated with the following code::

  plugins = InstalledSigmaPlugins.autodiscover()

This initates the object with all classes found by the autodiscovery process that utilizes the
mapping :ref:`described above <plugin-metadata>`. The plugin classes can then be referenced as
follows::

  plugins.backends["backend-indetifier"]
  plugins.pipelines["pipeline-indetifier"]
  plugins.validators["validator-indetifier"]

Further, a :ref:`pipeline resolver <pipeline-resolvers>` can be instantiated with::

  plugins.get_pipeline_resolver()

.. autoclass:: sigma.plugins.InstalledSigmaPlugins
   :members: