CREATE TABLE alert_labels (
  id INTEGER PRIMARY KEY,
  alert_id INTEGER NOT NULL REFERENCES alerts(id),
  label TEXT NOT NULL,
  source TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX ix_alert_labels_alert ON alert_labels(alert_id);
