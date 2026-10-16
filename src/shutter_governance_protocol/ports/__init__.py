"""The abstraction seams of the system.

- :mod:`shutter_governance_protocol.ports.data_layer` — ``ElectionDataLayer``, the single storage
  abstraction (chain / database / in-memory adapters).
- :mod:`shutter_governance_protocol.ports.eligibility` — ``EligibilityService``, the authority on who may
  vote and with what weight (wallet / OIDC / Wahlregister adapters).

These modules define contracts only. Adapters and services live in later slices.
"""
