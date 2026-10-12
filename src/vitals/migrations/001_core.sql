CREATE TABLE sessions (
  session_id     TEXT PRIMARY KEY,
  started_at     TEXT,
  ended_at       TEXT,
  end_reason     TEXT,
  source         TEXT,
  cwd            TEXT,
  git_branch     TEXT,
  cc_version     TEXT,
  model_default  TEXT,
  entrypoint     TEXT,
  plugins_hash   TEXT,
  settings_hash  TEXT,
  is_canary      INTEGER NOT NULL DEFAULT 0,
  transcript_path TEXT,
  num_turns      INTEGER,
  num_prompts    INTEGER NOT NULL DEFAULT 0,
  wall_seconds   REAL
);

CREATE TABLE api_requests (
  id             INTEGER PRIMARY KEY,
  session_id     TEXT NOT NULL,
  prompt_id      TEXT,
  request_id     TEXT,
  ts             TEXT NOT NULL,
  model          TEXT,
  effort         TEXT,
  speed          TEXT,
  query_source   TEXT,
  input_tokens   INTEGER, output_tokens INTEGER,
  cache_read_tokens INTEGER, cache_creation_tokens INTEGER,
  duration_ms    REAL,
  cost_usd       REAL,
  context_bucket TEXT,
  cc_version     TEXT,
  source         TEXT NOT NULL DEFAULT 'otel'
);
CREATE UNIQUE INDEX ux_api_requests_reqid ON api_requests(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX ix_api_requests_ts ON api_requests(ts);
CREATE INDEX ix_api_requests_prompt ON api_requests(prompt_id);

CREATE TABLE api_errors (
  id INTEGER PRIMARY KEY, session_id TEXT, prompt_id TEXT, request_id TEXT,
  ts TEXT NOT NULL, model TEXT, status_code INTEGER, attempt INTEGER,
  retries_exhausted INTEGER NOT NULL DEFAULT 0, error_text TEXT, duration_ms REAL, cc_version TEXT
);
CREATE INDEX ix_api_errors_ts ON api_errors(ts);

CREATE TABLE tool_results (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL, prompt_id TEXT, tool_use_id TEXT,
  ts TEXT NOT NULL, tool_name TEXT NOT NULL,
  success INTEGER,
  duration_ms REAL, error_type TEXT,
  file_path TEXT,
  bash_command_hash TEXT,
  bash_exit_code INTEGER,
  test_runner TEXT,
  tests_failed INTEGER,
  is_sidechain INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_tool_results_use ON tool_results(tool_use_id) WHERE tool_use_id IS NOT NULL;
CREATE INDEX ix_tool_results_ts ON tool_results(ts);
CREATE INDEX ix_tool_results_prompt ON tool_results(prompt_id);

CREATE TABLE compactions (
  id INTEGER PRIMARY KEY, session_id TEXT, ts TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'otel',
  trigger TEXT, success INTEGER, duration_ms REAL, pre_tokens INTEGER, post_tokens INTEGER
);
CREATE INDEX ix_compactions_ts ON compactions(ts);

CREATE TABLE transcript_turns (
  uuid TEXT PRIMARY KEY, session_id TEXT NOT NULL, parent_uuid TEXT,
  ts TEXT, role TEXT, model TEXT, effort TEXT, cc_version TEXT,
  request_id TEXT, prompt_id TEXT,
  input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
  stop_reason TEXT, is_sidechain INTEGER NOT NULL DEFAULT 0,
  self_corr_hits INTEGER NOT NULL DEFAULT 0,
  text_len INTEGER
);
CREATE INDEX ix_transcript_turns_session ON transcript_turns(session_id);
CREATE INDEX ix_transcript_turns_ts ON transcript_turns(ts);

CREATE TABLE canary_cycles (
  cycle_id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL, finished_at TEXT,
  model TEXT NOT NULL, effort TEXT NOT NULL, cc_version TEXT, suite_hash TEXT NOT NULL,
  n_runs INTEGER, n_pass INTEGER, n_invalid INTEGER,
  pass_rate REAL,
  tokens_in INTEGER, tokens_out INTEGER, cost_usd REAL,
  aborted_reason TEXT
);

CREATE TABLE canary_runs (
  run_id INTEGER PRIMARY KEY, cycle_id INTEGER NOT NULL REFERENCES canary_cycles(cycle_id),
  task_id TEXT NOT NULL, attempt INTEGER NOT NULL,
  session_id TEXT, ts TEXT NOT NULL, model TEXT,
  passed INTEGER, invalid INTEGER NOT NULL DEFAULT 0, fail_detail TEXT,
  duration_ms REAL, duration_api_ms REAL, ttft_ms REAL, num_turns INTEGER,
  input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER, cost_usd REAL,
  terminal_reason TEXT, is_error INTEGER, subtype TEXT, result_sha TEXT
);
CREATE INDEX ix_canary_runs_cycle ON canary_runs(cycle_id);

CREATE TABLE incidents (
  incident_id TEXT PRIMARY KEY, name TEXT, status TEXT, impact TEXT,
  created_at TEXT, resolved_at TEXT, components TEXT, raw_json TEXT, last_seen TEXT
);

CREATE TABLE change_points (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  old_value TEXT, new_value TEXT, detail TEXT
);
CREATE INDEX ix_change_points_ts ON change_points(ts);

CREATE TABLE signal_windows (
  id INTEGER PRIMARY KEY,
  window_start TEXT NOT NULL,
  signal TEXT NOT NULL,
  model TEXT NOT NULL, context_bucket TEXT NOT NULL,
  value REAL NOT NULL, n INTEGER NOT NULL,
  cc_version TEXT NOT NULL DEFAULT 'unknown'
);
CREATE UNIQUE INDEX ux_signal_windows
  ON signal_windows(window_start, signal, model, context_bucket, cc_version);

CREATE TABLE detector_state (
  signal TEXT NOT NULL, model TEXT NOT NULL, context_bucket TEXT NOT NULL,
  cc_version TEXT NOT NULL,
  mu0 REAL, sigma0 REAL, baseline_start TEXT, baseline_end TEXT, baseline_n INTEGER,
  baseline_inherited_from TEXT,
  ewma REAL, cusum_pos REAL NOT NULL DEFAULT 0, cusum_neg REAL NOT NULL DEFAULT 0,
  in_alarm INTEGER NOT NULL DEFAULT 0, frozen INTEGER NOT NULL DEFAULT 0,
  last_window TEXT,
  PRIMARY KEY (signal, model, context_bucket, cc_version)
);

CREATE TABLE anomalies (
  id INTEGER PRIMARY KEY, signal TEXT NOT NULL, model TEXT, context_bucket TEXT,
  started_at TEXT NOT NULL, ended_at TEXT, direction TEXT, peak_stat REAL,
  status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL,
  severity TEXT NOT NULL,
  attribution TEXT NOT NULL,
  title TEXT NOT NULL, evidence_json TEXT NOT NULL,
  anomaly_ids TEXT,
  suppressed_by_incident TEXT,
  report_path TEXT, acked_at TEXT, resolved_at TEXT,
  resolution TEXT
);

CREATE TABLE spend_ledger (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, day TEXT NOT NULL,
  source TEXT NOT NULL,
  tokens_in INTEGER, tokens_out INTEGER, cost_usd REAL, cum_day_usd REAL
);
CREATE INDEX ix_spend_ledger_day ON spend_ledger(day);

CREATE TABLE ingest_log (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL,
  ok_count INTEGER, err_count INTEGER, detail TEXT
);
CREATE INDEX ix_ingest_log_ts ON ingest_log(ts);

CREATE TABLE vitals_kv (key TEXT PRIMARY KEY, value TEXT);
