Reformat the meeting note below into exactly 5 lines, in this strict format:

Line 1: `DATE: <YYYY-MM-DD>` — the date the sync took place.
Line 2: `ATTENDEES: <integer>` — the number of people present.
Line 3: `DECISION: <sentence>` — the decision clause from the note, transformed as follows:
    drop any leading meta-phrase such as "We decided to" or "It was decided that", capitalize
    the first letter of what remains, and end it with a single period. Do not include the
    words "decided" or "we" anywhere in the output. Example (not from the note below): if the
    note said "We decided to migrate the database to Postgres.", this line would read
    `DECISION: Migrate the database to Postgres.`
Line 4: `ACTION_OWNER: <name>` — the single person who owns the follow-up action.
Line 5: `DUE: <YYYY-MM-DD>` — the deadline for that action.

Meeting note:

Notes from the Aug 12 sync (2026-08-12): Present were Priya, Marcus, and Jo (3 people). We
decided to switch the export job to run hourly instead of daily. Marcus owns wiring up the
cron change and will have it done by August 19, 2026.

Output exactly those 5 lines, in that order, with those exact field labels — no blank lines,
no extra commentary before or after, no markdown formatting.
