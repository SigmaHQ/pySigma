Breaking Changes
================

This page documents breaking changes in pySigma. Normally, we try to avoid breaking changes in minor
versions and generally try to keep pySigma backwards compatible, but sometimes they are necessary to
improve the library.

Version 1.0
-----------

* The class `CompareOperators` was moved out of `SigmaCompatreExpression` into the root of the
  containing module `sigma.types`. If the class was formerly used, it has now to be imported
  explicitly from the module.