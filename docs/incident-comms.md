# Paid-Tenant Incident Communications

Use this for incidents that affect a paid tenant, design partner, hosted
revocation path, billing/entitlement path, usage receipts, or a customer-facing
control-plane surface. It is a communications runbook, not the technical RCA.
Keep root cause, commands, receipt ids, and fixes in the owning ExecPlan and in
an `incident:YYYY-MM-DD` fact.

## Status Page Gate

Status page provider, public URL, and staffing owner are still a launch gate.
Until that decision is recorded, publish updates through the staffed support
channel chosen for launch and mirror the text into the incident record.

Do not publish secrets, tenant-private content, raw tokens, passport private
keys, customer prompts, or unredacted request bodies.

## Severity

| Level | Customer impact | First update | Cadence |
| --- | --- | --- | --- |
| SEV-1 | Broad outage, data integrity risk, or paid control plane unavailable | 15 minutes | 30 minutes |
| SEV-2 | Single-tenant outage, degraded entitlement/billing, or revocation delay | 30 minutes | 60 minutes |
| SEV-3 | Partial degradation, delayed receipts, or non-critical console issue | 1 business day | Daily |

## First Update Template

```text
Subject: CueCrux incident update: <short title>

Status: Investigating
Severity: <SEV-1|SEV-2|SEV-3>
Started: <UTC timestamp>
Affected surface: <daemon|control plane|billing|revocation|usage receipts|other>
Affected tenants: <all|named tenant(s)|under investigation>

We are investigating <plain-language symptom>. Current customer impact is
<specific impact>. We have not found evidence of <data loss|cross-tenant access|
unauthorized access> at this time. If that changes, we will update this notice.

Mitigation underway: <what we are doing now>
Next update by: <UTC timestamp>
```

## Progress Update Template

```text
Subject: CueCrux incident update: <short title>

Status: <Investigating|Mitigating|Monitoring>
Updated: <UTC timestamp>

What changed:
- <new fact, mitigation, or narrowed impact>

Current impact:
- <who/what remains affected>

Next:
- <next concrete action>

Next update by: <UTC timestamp>
```

## Resolution Template

```text
Subject: CueCrux incident resolved: <short title>

Status: Resolved
Resolved at: <UTC timestamp>
Duration: <duration>
Affected surface: <surface>
Affected tenants: <all|named tenant(s)>

Impact:
- <customer-visible impact>

Resolution:
- <plain-language fix or rollback>

Follow-up:
- <RCA timing, customer action if any, permanent fix>
```

## Internal Closure Checklist

- Store or update `incident:YYYY-MM-DD` with symptom, cause, fix_sha, and
  repro_steps. Do not include secret values.
- Link the incident fact from the owning ExecPlan gate or milestone.
- Confirm customer-visible mitigation with the same endpoint or workflow that
  failed.
- Record whether support, status page, sales, and affected tenants were updated.
- If receipts, billing, entitlements, revocation, or erasure were involved,
  attach the relevant receipt ids or audit artifact paths to the ExecPlan.
