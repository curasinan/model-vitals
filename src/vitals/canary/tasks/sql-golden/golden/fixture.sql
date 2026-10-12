CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL
);

INSERT INTO orders (id, name, total, status) VALUES
    (1, 'Alice', 120.00, 'shipped'),
    (2, 'Bob', 75.50, 'pending'),
    (3, 'Carla', 203.25, 'shipped'),
    (4, 'Devon', 45.00, 'cancelled'),
    (5, 'Elena', 310.00, 'shipped'),
    (6, 'Farid', 99.75, 'pending'),
    (7, 'Grace', 150.00, 'shipped'),
    (8, 'Hana', 60.00, 'cancelled');
