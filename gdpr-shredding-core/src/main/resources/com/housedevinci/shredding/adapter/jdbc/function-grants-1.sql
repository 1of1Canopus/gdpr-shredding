-- C-PR45-3, statement 1: the shipped record of functions, and the installed extensions.
-- Facts only: Java applies R0, R1, R2, R4 and R5v to the rows (FunctionGrants).
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
-- Binds: 1 baseline oids (_oid); 2 extension names with an ok line (_text);
--        3 ok (extension, version) pairs joined by a tab (_text).
SELECT 'fn'::pg_catalog.text AS kind,
       p.oid AS oid,
       i.privtype::pg_catalog.text AS privtype,
       (SELECT pg_catalog.string_agg(pg_catalog.concat(
                 CASE WHEN (y.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid) THEN 'PUBLIC'
                      WHEN (y.grantee OPERATOR(pg_catalog.=) 10::pg_catalog.oid) THEN '@owner'
                      WHEN r.rolname IS NULL THEN pg_catalog.concat('#', y.grantee)
                      ELSE r.rolname::pg_catalog.text END,
                 '=',
                 CASE WHEN (y.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE') THEN 'X'
                      ELSE y.privilege_type END,
                 CASE WHEN y.is_grantable THEN '*' ELSE '' END), ',')
          FROM pg_catalog.aclexplode(i.initprivs) AS y
          LEFT JOIN pg_catalog.pg_roles AS r ON (r.oid OPERATOR(pg_catalog.=) y.grantee)) AS acl,
       EXISTS (SELECT 1 FROM pg_catalog.aclexplode(i.initprivs) AS y
                WHERE (y.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)) AS names_public,
       EXISTS (SELECT 1 FROM pg_catalog.aclexplode(i.initprivs) AS y
                WHERE (y.grantee OPERATOR(pg_catalog.>=) 16384::pg_catalog.oid)) AS names_late,
       (l.lanname OPERATOR(pg_catalog.=) ANY ('{internal,c}'::pg_catalog._name)) AS native,
       pg_catalog.concat(n.nspname, '.', p.proname, '(',
                         pg_catalog.pg_get_function_identity_arguments(p.oid), ')') AS signature,
       pg_catalog.concat(p.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(p.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')') AS key,
       p.prosrc AS symbol,
       p.prosecdef AS secdef,
       NULL::pg_catalog.text AS extname,
       NULL::pg_catalog.text AS extversion,
       NULL::pg_catalog.text AS targets
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.pronamespace)
  JOIN pg_catalog.pg_language AS l ON (l.oid OPERATOR(pg_catalog.=) p.prolang)
  LEFT JOIN pg_catalog.pg_init_privs AS i
         ON (i.objoid OPERATOR(pg_catalog.=) p.oid)
        AND (i.classoid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass)
        AND (i.objsubid OPERATOR(pg_catalog.=) 0)
 WHERE (i.objoid IS NOT NULL) OR (p.oid OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
UNION ALL
SELECT 'ext', e.oid, NULL::pg_catalog.text, NULL::pg_catalog.text, false, false, false,
       NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text, false,
       e.extname::pg_catalog.text, e.extversion,
       -- R5v remedy: only for a shipped extension at a version with no ok line (C-PR45-3-14)
       CASE WHEN (e.extname::pg_catalog.text OPERATOR(pg_catalog.=) ANY (?::pg_catalog._text))
             AND NOT (pg_catalog.concat(e.extname, pg_catalog.chr(9), e.extversion)
                      OPERATOR(pg_catalog.=) ANY (?::pg_catalog._text))
            THEN (SELECT pg_catalog.string_agg(u.target, pg_catalog.chr(9))
                    FROM pg_catalog.pg_extension_update_paths(e.extname) AS u
                   WHERE (u.source OPERATOR(pg_catalog.=) e.extversion) AND (u.path IS NOT NULL))
       END
  FROM pg_catalog.pg_extension AS e
 ORDER BY 1, 2
