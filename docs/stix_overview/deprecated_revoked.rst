Working with deprecated and revoked objects
===============

**Working with deprecated and revoked objects**

Objects that are deemed no longer beneficial to track as part of the knowledge base are marked as deprecated, and objects which are replaced by a different object are revoked. In both cases, the old object is marked with a field (either `x_mitre_deprecated` or `revoked`) noting their status. In the case of revoked objects, a relationship of type `revoked-by` is also created targeting the replacing object.

Unlike other objects in the dataset, relationships cannot be revoked or deprecated. Relationships are considered deprecated/revoked if one of the objects it is attached to is revoked or deprecated.