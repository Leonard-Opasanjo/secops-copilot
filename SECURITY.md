# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Leonard-Opasanjo/secops-copilot/security/advisories/new>.
Include the case data (alerts and logs) that triggers the problem and the backend you used. You should hear back
within seven days.

## In scope

- Any way for case data (alerts, log lines, titles) to make an action execute without a human approval recorded
  in the audit trail, or to change an action's status.
- Any way for case data to make the analysis state a "fact" whose evidence references do not exist, or to
  suppress the injection fact when the data contains instruction-like text the detector should catch.
- A credential format that the redactor should reasonably catch reaching the outgoing request.
- Cross-site scripting or injection in the dashboard or the report through case data, notes or names.
- The connector being reachable through any path other than `Store.execute` on an approved action.

## Out of scope

- The dashboard having no authentication; it is a local tool bound to `127.0.0.1`.
- The approver's name being a typed field. Identity binding is a deployment concern (reverse proxy); the
  README says so.
- Detection gaps in the offline analyst and subtle injections that the pattern detector does not match; these
  are improvements, not vulnerabilities, unless they defeat the validator or the gate.
- Behaviour of the Claude model itself.

## Design notes for reviewers

The validator in `secops_copilot/models.py` and the gate in `secops_copilot/db.py` are the two places where
trust is decided. Everything a model returns and everything a user submits passes through the first; everything
that could touch a system passes through the second.
