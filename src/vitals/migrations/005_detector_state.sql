ALTER TABLE anomalies ADD COLUMN cc_version TEXT;

ALTER TABLE detector_state ADD COLUMN baseline_samples INTEGER;
ALTER TABLE detector_state ADD COLUMN below_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detector_state ADD COLUMN open_anomaly_id INTEGER;
ALTER TABLE detector_state ADD COLUMN healthy_from TEXT;
ALTER TABLE detector_state ADD COLUMN k_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detector_state ADD COLUMN last_cycle_id INTEGER;

CREATE INDEX ix_signal_windows_stratum
  ON signal_windows(signal, model, context_bucket, cc_version, window_start);
CREATE INDEX ix_anomalies_stratum
  ON anomalies(signal, model, context_bucket, cc_version);
