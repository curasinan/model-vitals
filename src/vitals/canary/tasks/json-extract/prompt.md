You are triaging an incoming support ticket. Read the ticket below, classify it using the
rubric, and output a single JSON object.

## Priority rubric

- `critical`: a complete outage (0% of requests succeeding) or active data loss.
- `high`: partial degradation affecting a paying customer's production traffic, especially
  when the ticket explicitly claims an SLA or contractual response-time breach, or explicitly
  asks for urgent/Sev-1 handling.
- `medium`: an isolated bug affecting a non-critical feature, with no SLA or urgency language.
- `low`: a cosmetic issue or a general question with no reported business impact.

## `sla_breach` rubric

Set `sla_breach` to `true` only if the ticket text explicitly states that an SLA, uptime
commitment, or contractual response-time has already been breached or is about to be missed.
Otherwise set it to `false`. Do not infer a breach from severity alone — it must be stated.

## Ticket

Ticket #4471
Subject: Production API returning intermittent 500 errors since deploy

Customer: Meridian Logistics (Enterprise plan)
Submitted: 2026-08-19 14:32 UTC
Channel: Email

Description:
Since this morning's deployment (v2.14.0, rolled out at 09:00 UTC), our
integration has been receiving intermittent HTTP 500 errors on the
/v1/shipments/create endpoint. Roughly 1 in 20 requests fail. Retrying
the same request usually succeeds on the second or third attempt. We
have not changed anything on our end. This is delaying same-day
shipments for approximately 40 orders so far today.

Error sample returned to us:
  {"error": "internal_server_error", "request_id": "a83f-771c"}

We are on the Enterprise plan with a contractual 99.9% uptime SLA. Given the customer-facing impact and the breach of our SLA window, please treat this as urgent and provide a status update within the hour.
Reported by: Dana Whitfield, Platform Engineering Lead

## Output format

Respond with exactly one fenced code block, tagged `json`, containing a JSON object with
exactly two keys, `priority` and `sla_breach`, matching this schema:

```json
{
  "type": "object",
  "required": ["priority", "sla_breach"],
  "properties": {
    "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "sla_breach": {"type": "boolean"}
  },
  "additionalProperties": false
}
```

Output nothing before or after that code block — no explanation, no restated ticket text.
