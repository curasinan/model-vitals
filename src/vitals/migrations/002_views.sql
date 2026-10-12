CREATE VIEW v_edit_loops AS
  SELECT session_id, prompt_id, file_path, COUNT(*) AS edits, MIN(ts) AS first_ts
  FROM tool_results
  WHERE tool_name IN ('Edit','Write','NotebookEdit') AND file_path IS NOT NULL
        AND prompt_id IS NOT NULL AND is_sidechain = 0
  GROUP BY session_id, prompt_id, file_path;

CREATE VIEW v_compaction_episodes AS
  SELECT session_id,
         MIN(ts) AS ts,
         MAX(trigger) AS trigger,
         MAX(CASE WHEN source='otel' THEN pre_tokens END)  AS pre_tokens,
         MAX(CASE WHEN source='otel' THEN post_tokens END) AS post_tokens,
         MAX(CASE WHEN source='otel' THEN success END)     AS success
  FROM compactions
  GROUP BY session_id, CAST(strftime('%s', ts) / 300 AS INTEGER);

CREATE VIEW v_post_compaction_turns AS
  SELECT tr.* FROM tool_results tr JOIN v_compaction_episodes c
    ON tr.session_id = c.session_id
   AND CAST(strftime('%s', tr.ts) AS INTEGER) >= CAST(strftime('%s', c.ts) AS INTEGER)
   AND CAST(strftime('%s', tr.ts) AS INTEGER) <= CAST(strftime('%s', c.ts) AS INTEGER) + 900;
