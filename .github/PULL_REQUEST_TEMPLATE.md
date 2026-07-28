## Detection Rule PR

### Summary
<!-- One sentence: what technique does this detect, and how? -->


### MITRE ATT&CK
| Field | Value |
|-------|-------|
| Technique ID | <!-- e.g. T1105 --> |
| Technique Name | <!-- e.g. Ingress Tool Transfer --> |
| Tactic | <!-- e.g. command-and-control --> |
| Sub-technique | <!-- e.g. .001 or N/A --> |

---

## Checklist

### Detection Rule
- [ ] Rule file is at `detections/linux/<tactic>/<TECHNIQUE_ID>.yml`
- [ ] Sigma `title`, `id` (UUID), `status`, `description`, `author`, `date` are populated
- [ ] `tags` include both `attack.<tactic>` and `attack.t<id>` (lowercase)
- [ ] `logsource` is correct (`product: linux`, `service: auditd`)
- [ ] Detection logic tested manually — no false positives from baseline traffic
- [ ] `falsepositives` section is populated
- [ ] `level` is set appropriately (low/medium/high/critical)

### Wazuh Rule
- [ ] Corresponding XML rule added with a unique `id` (next in 1000xx sequence)
- [ ] `<mitre><id>` block populated
- [ ] `<group>` tag includes `attack,<tactic>,t<id>,`
- [ ] Rule deployed to Wazuh and verified in dashboard

### Atomic Test
- [ ] `atomic-tests/linux/<TECHNIQUE_ID>/expected_alert.json` created
- [ ] `atomic_command` is the exact command fired on emulation VM
- [ ] `cleanup_command` removes any artifacts
- [ ] `expected_fields` validated against a real alert in Wazuh

### CI/CD
- [ ] Lint workflow passes (YAML valid)
- [ ] Test workflow passes (alert detected and validated)
- [ ] Deploy workflow passes (rule deployed without errors)
- [ ] `policies/mitre_coverage_map.md` updated with new technique

### Documentation
- [ ] Rule description is clear enough for an analyst with no context
- [ ] False positive guidance is actionable

---

## Test Evidence
<!-- Paste the alert_validator.py output or a screenshot from the Wazuh dashboard -->
