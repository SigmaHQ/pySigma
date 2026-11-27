Modifiers
=========

The modifiers module implements Sigma detection value modifiers that transform values
during rule parsing.

The ``utf16le`` and ``wide`` names both use :class:`~sigma.modifiers.SigmaWideModifier`
to encode values as UTF-16LE without a byte order mark. They can be combined with
``base64`` or ``base64offset``. Serialization continues to use the existing ``wide``
spelling for both names.

Base Classes
------------

.. autoclass:: sigma.modifiers.SigmaModifier
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.modifiers.SigmaValueModifier
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.modifiers.SigmaListModifier
   :members:
   :undoc-members:
   :show-inheritance:

Modifier Classes
----------------

.. automodule:: sigma.modifiers
   :members:
   :undoc-members:
   :show-inheritance:
   :exclude-members: SigmaModifier, SigmaValueModifier, SigmaListModifier
