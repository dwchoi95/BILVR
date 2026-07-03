-- Extract one row per (CVE, vulnerable function) from the MoreFixes Postgres DB.
-- Pairs the before-fix (vulnerable) and after-fix (patched) versions of each
-- method via a self-join on method_change, keyed by file_change + method name.
-- Emits the raw fields BILVR needs; CWE text and Vulnerable Lines are added by
-- the Python post-processor (morefixes_adapter.py), which has the MITRE catalog
-- and the diff parser.
COPY (
  -- Drop noisy mega-commits: a commit linked to many CVEs is almost always a
  -- sync/merge/import, not a targeted fix. Keep commits tied to <= 3 CVEs.
  WITH clean_hash AS (
    SELECT hash FROM public.fixes GROUP BY hash HAVING count(DISTINCT cve_id) <= 3
  )
  -- Pair before/after method versions on (file_change_id, name, signature),
  -- which is UNIQUE per before_change flag -> no cartesian blow-up.
  SELECT DISTINCT ON (c.cve_id, fc.file_change_id, mb.name, mb.signature)
    c.cve_id                AS "CVE ID",
    c.published_date        AS published_date,
    c.description           AS "CVE Description",
    cc.cwe_id               AS "CWE ID",
    lower(fc.programming_language) AS "Programming Language",
    mb.start_line           AS start_line,
    mb.end_line             AS end_line,
    mb.code                 AS "Vulnerable Code",
    ma.code                 AS "Human Patch",
    fc.diff_parsed          AS diff_parsed
  FROM public.cve c
  JOIN public.cwe_classification cc ON cc.cve_id = c.cve_id
  JOIN public.fixes f               ON f.cve_id  = c.cve_id
  JOIN clean_hash ch                ON ch.hash   = f.hash
  JOIN public.file_change fc        ON fc.hash   = f.hash
  JOIN public.method_change mb      ON mb.file_change_id = fc.file_change_id
                                   AND mb.before_change = 'True'
  JOIN public.method_change ma      ON ma.file_change_id = fc.file_change_id
                                   AND ma.before_change = 'False'
                                   AND ma.name = mb.name
                                   AND ma.signature IS NOT DISTINCT FROM mb.signature
  WHERE mb.code IS NOT NULL AND ma.code IS NOT NULL
    AND btrim(mb.code) <> btrim(ma.code)
    AND fc.programming_language IS NOT NULL AND btrim(fc.programming_language) <> ''
    AND cc.cwe_id LIKE 'CWE-%'
  ORDER BY c.cve_id, fc.file_change_id, mb.name, mb.signature, cc.cwe_id
) TO STDOUT WITH (FORMAT CSV, HEADER);
