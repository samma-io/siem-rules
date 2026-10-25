# Samma SIEM Rules

> [!WARNING]
> **This repo is frozen.** The rules now live in
> [samma-io/detection-engine](https://github.com/samma-io/detection-engine) as
> Sigma rules, each with a `.tests.yml`:
>
> - [`rules/k8s`](https://github.com/samma-io/detection-engine/tree/main/rules/k8s):
>   all 27 Kubernetes audit rules from `rules/k8s/` here.
> - [`rules/scanner`](https://github.com/samma-io/detection-engine/tree/main/rules/scanner):
>   the nmap and nikto rules from `rules/nmap/` and `rules/nikto/` here.
>
> The custom YAML engine these rules were written for (samma-io/siem) is
> deprecated in favour of `chart/samma-siem` plus detection-engine; see
> [samma-io/siem#4](https://github.com/samma-io/siem/issues/4). Do not add or
> change rules here. Open them in detection-engine instead. This repo will be
> archived after a release with the new stack.
>
> The production deploy workflow (`.github/workflows/deploy.yml`) has been
> removed. Nothing in this repo deploys anywhere any more.

The rest of this README describes the legacy rule format and is kept for reference.

A collection of SIEM detection rules for the [Samma](https://samma.io) security platform. Rules are defined in YAML and match against security events from various sources including Kubernetes audit logs, Nmap scans, and Nikto web vulnerability scans.

## Project Structure

```
siem-rules/
├── rules/            # Detection rules in YAML format
│   ├── k8s/          # Kubernetes audit log rules
│   ├── nmap/         # Nmap port scan rules
│   └── nikto/        # Nikto web scanner rules
├── test/             # Test fixtures (JSON events) for each rule
│   ├── k8s/
│   ├── nmap/
│   └── nikto/
└── .github/workflows # rule validation (test) and release archives only
```

## Rule Format

Each rule is a YAML file with the following structure:

```yaml
name: rule-name
description: Human-readable description of what the rule detects
severity: low | medium | high | critical
nats_subject: samma.alerts.<category>.<type>

compliance:
  pci_dss: [...]
  gdpr: [...]
  hipaa: [...]
  nist_800_53: [...]
  mitre: [...]       # MITRE ATT&CK technique IDs
  tsc: [...]
  gpg13: [...]

match:
  and:
    - field: <dotted.field.path>
      equals: <value>
    - field: <dotted.field.path>
      regex: "<pattern>"
```

### Fields

| Field | Description |
|---|---|
| `name` | Unique identifier for the rule |
| `description` | What the rule detects |
| `severity` | Alert severity: `low`, `medium`, `high`, or `critical` |
| `nats_subject` | NATS subject where matching alerts are published |
| `compliance` | Mapping to compliance frameworks (PCI DSS, GDPR, HIPAA, NIST 800-53, MITRE ATT&CK, TSC, GPG13) |
| `match` | Matching logic using `and`/`or` with `equals` or `regex` conditions |

### Match Conditions

- **`equals`** — Exact string match against a field value
- **`regex`** — Regular expression match against a field value
- **`field`** — Supports dot-notation for nested fields (e.g., `objectRef.resource`)

## Current Rules

| Rule | Source | Severity | Description |
|---|---|---|---|
| `k8s-user-login` | Kubernetes | Medium | Alerts on Kubernetes user authentication events |
| `nmap-open-port` | Nmap | Medium | Matches nmap port scan results for open TCP ports |
| `nikto-critical-finding` | Nikto | High | Matches Nikto findings with known OSVDB vulnerabilities |

## Usage

### Download a Release

Download a specific version of the rules from the [Releases](https://github.com/samma-io/siem-rules/releases) page:

```bash
# Download a specific version
curl -L -o siem-rules-v0.1.0.tar.gz \
  https://github.com/samma-io/siem-rules/releases/download/v0.1.0/siem-rules-v0.1.0.tar.gz
```

### Running Tests

Tests validate that each rule correctly matches its corresponding test fixture:

```bash
pip install pyyaml
python test_rules.py
```

## Adding a New Rule (legacy, do not use)

New rules go in samma-io/detection-engine. The steps below are the legacy process.

1. Create a YAML rule file under `rules/<category>/`:
   ```yaml
   name: my-new-rule
   description: Detects something important
   severity: high
   nats_subject: samma.alerts.category.type

   compliance:
     mitre:
       - "T1234"

   match:
     and:
       - field: type
         equals: my_source
   ```

2. Add a matching test fixture under `test/<category>/` as a JSON file containing a sample event that should match the rule.

3. Run `python test_rules.py` to verify the rule matches the test data.

## Releases

Releases are automatically created when a version tag is pushed:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Each release includes a downloadable `siem-rules-<version>.tar.gz` archive containing all rules.

## License

Copyright Samma.io. All rights reserved.
