You have a SQLite table named `orders` with this schema:

    CREATE TABLE orders (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        total REAL NOT NULL,
        status TEXT NOT NULL
    );

Write a single SQL `SELECT` statement that returns the `name` and `total` of every order whose
`total` is greater than 100, ordered by `name` ascending.

Respond with only the SQL statement — no markdown code fence, no explanation, no trailing
semicolon required (either is fine), and no other statements.
