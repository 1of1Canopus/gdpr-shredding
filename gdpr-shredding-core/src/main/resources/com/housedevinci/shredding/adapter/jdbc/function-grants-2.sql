-- C-PR45-3, statement 2: who in reach, or PUBLIC, may execute native code or a function
-- with a shipped record. One row per (function, grantee); a function nobody of interest may
-- execute still gives one row with a NULL grantee, so its symbol is known (leg 2, the generator).
-- Facts only: Java applies legs 1 to 3, R3, R5a and R5b to the rows (FunctionGrants).
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
-- Binds: 1 reach oids (_oid); 2 baseline oids (_oid).
SELECT p.oid AS oid,
       pg_catalog.concat(n.nspname, '.', p.proname, '(',
                         pg_catalog.pg_get_function_identity_arguments(p.oid), ')') AS label,
       g.grantee AS grantee,
       i.privtype::pg_catalog.text AS privtype,
       EXISTS (SELECT 1 FROM pg_catalog.aclexplode(i.initprivs) AS y
                WHERE (y.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
                  AND (y.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')) AS shipped_public,
       (l.lanname OPERATOR(pg_catalog.=) ANY ('{internal,c}'::pg_catalog._name)) AS native,
       l.lanname::pg_catalog.text AS language,
       p.prosrc AS symbol,
       p.prosecdef AS secdef,
       e.extname::pg_catalog.text AS extname,
       e.extversion AS extversion,
       pg_catalog.concat(p.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(p.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')') AS key,
       p.proowner AS owner,
       pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text AS owner_name,
       p.prokind::pg_catalog.text AS kind
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.pronamespace)
  JOIN pg_catalog.pg_language AS l ON (l.oid OPERATOR(pg_catalog.=) p.prolang)
  LEFT JOIN pg_catalog.pg_init_privs AS i
         ON (i.objoid OPERATOR(pg_catalog.=) p.oid)
        AND (i.classoid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass)
        AND (i.objsubid OPERATOR(pg_catalog.=) 0)
  LEFT JOIN pg_catalog.pg_depend AS d
         ON (d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass)
        AND (d.objid OPERATOR(pg_catalog.=) p.oid)
        AND (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_extension'::pg_catalog.regclass)
        AND (d.deptype OPERATOR(pg_catalog.=) 'e')
  LEFT JOIN pg_catalog.pg_extension AS e ON (e.oid OPERATOR(pg_catalog.=) d.refobjid)
  -- A function in FROM sees the items before it, so no LATERAL keyword is needed.
  LEFT JOIN pg_catalog.aclexplode(CASE WHEN p.proacl IS NULL
                                       THEN pg_catalog.acldefault('f', p.proowner)
                                       ELSE p.proacl END) AS g
         ON (g.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
        AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
             OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid)))
 WHERE (l.lanname OPERATOR(pg_catalog.=) ANY ('{internal,c}'::pg_catalog._name))
    OR (i.objoid IS NOT NULL)
    OR (p.oid OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
 ORDER BY 1, 3
