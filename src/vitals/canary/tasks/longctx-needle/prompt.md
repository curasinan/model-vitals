You are given a service log below, delimited by the markers `===LOG START===` and
`===LOG END===`. Using ONLY the content of that log, answer the following four questions.

1. What is the status of ORDER-240891?
2. What is the status of ORDER-696853?
3. What is the status of ORDER-988598?
4. How many `PaymentGatewayTimeout` errors appear in the log? Count every log line whose
   `class=` field is exactly `PaymentGatewayTimeout` (not any other error class).

Each order's status is recorded in a line containing `order=<that order id> status=<STATUS>`;
use the literal status token exactly as it appears in the log. It is always one uppercase
word (for example DELIVERED, CANCELLED, SHIPPED, PENDING, REFUNDED, or BACKORDERED) -- do
not translate, lowercase, or paraphrase it.

Output exactly 4 lines, in this exact order, and nothing else -- no commentary, no
markdown formatting, no code fence, no restating the questions:

ORDER-240891: <STATUS>
ORDER-696853: <STATUS>
ORDER-988598: <STATUS>
PaymentGatewayTimeout: <COUNT>

Replace each `<STATUS>` with that order's literal status word, and `<COUNT>` with the plain
integer count -- digits only, no leading zeros, no thousands separators, no decimal point.
Do not include the angle brackets in your answer.

===LOG START===
{LOG}
===LOG END===
