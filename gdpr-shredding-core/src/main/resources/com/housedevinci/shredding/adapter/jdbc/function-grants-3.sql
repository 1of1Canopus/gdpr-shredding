-- C-PR45-3, statement 3: caller objects (design revision 5, rule R6). One row per (object,
-- slot, support function): a catalogue row that names a function the server calls for you.
-- Aggregates (eight slots), operators (code, restrict, join) and languages (handler, inline,
-- validator). The slot is the 1-based position in that list; FunctionGrants names it.
-- Facts only: Java decides which slots run with the owner's rights, or with no EXECUTE
-- check, and judges their functions (FunctionGrants).
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
-- Binds: 1 and 2 reach oids (_oid), for the aggregate and the language branch.
SELECT 'agg'::pg_catalog.text AS kind,
       p.oid AS oid,
       pg_catalog.concat(n.nspname, '.', p.proname, '(',
                         pg_catalog.pg_get_function_identity_arguments(p.oid), ')') AS label,
       p.proowner AS owner,
       pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text AS owner_name,
       EXISTS (SELECT 1 FROM pg_catalog.aclexplode(CASE WHEN p.proacl IS NULL
                                                        THEN pg_catalog.acldefault('f', p.proowner)
                                                        ELSE p.proacl END) AS g
                WHERE (g.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
                  AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
                       OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid)))) AS usable,
       s.ordinality AS slot,
       f.oid AS fn,
       pg_catalog.concat(f.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(f.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')') AS fn_key
  FROM pg_catalog.pg_aggregate AS a
  JOIN pg_catalog.pg_proc AS p ON (p.oid OPERATOR(pg_catalog.=) a.aggfnoid)
  JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.pronamespace)
  -- A function in FROM sees the items before it, so no LATERAL keyword is needed.
  CROSS JOIN pg_catalog.unnest(
         pg_catalog.array_cat(
           pg_catalog.array_cat(
             pg_catalog.array_cat(
               pg_catalog.array_append(pg_catalog.array_append('{}'::pg_catalog._oid,
               a.aggtransfn::pg_catalog.oid), a.aggfinalfn::pg_catalog.oid),
             pg_catalog.array_append(pg_catalog.array_append('{}'::pg_catalog._oid,
               a.aggcombinefn::pg_catalog.oid), a.aggserialfn::pg_catalog.oid)),
             pg_catalog.array_append(pg_catalog.array_append('{}'::pg_catalog._oid,
               a.aggdeserialfn::pg_catalog.oid), a.aggmtransfn::pg_catalog.oid)),
           pg_catalog.array_append(pg_catalog.array_append('{}'::pg_catalog._oid,
             a.aggminvtransfn::pg_catalog.oid), a.aggmfinalfn::pg_catalog.oid)))
               WITH ORDINALITY AS s
  -- A slot the aggregate leaves empty is oid 0, which no function has: the join drops it.
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) s.s)
UNION ALL
-- Operators have no ACL: anyone who can name one can use it.
SELECT 'opr', o.oid, o.oid::pg_catalog.regoperator::pg_catalog.text, o.oprowner,
       pg_catalog.pg_get_userbyid(o.oprowner)::pg_catalog.text, true, s.ordinality, f.oid,
       pg_catalog.concat(f.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(f.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')')
  FROM pg_catalog.pg_operator AS o
  CROSS JOIN pg_catalog.unnest(
         pg_catalog.array_append(pg_catalog.array_append(pg_catalog.array_append(
           '{}'::pg_catalog._oid, o.oprcode::pg_catalog.oid), o.oprrest::pg_catalog.oid),
           o.oprjoin::pg_catalog.oid)) WITH ORDINALITY AS s
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) s.s)
UNION ALL
-- A language is usable by a role that is not a superuser only when it is trusted.
SELECT 'lang', l.oid, l.lanname::pg_catalog.text, l.lanowner,
       pg_catalog.pg_get_userbyid(l.lanowner)::pg_catalog.text,
       (l.lanpltrusted
        AND EXISTS (SELECT 1
                      FROM pg_catalog.aclexplode(CASE WHEN l.lanacl IS NULL
                                                      THEN pg_catalog.acldefault('l', l.lanowner)
                                                      ELSE l.lanacl END) AS g
                     WHERE (g.privilege_type OPERATOR(pg_catalog.=) 'USAGE')
                       AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
                            OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))))),
       s.ordinality, f.oid,
       pg_catalog.concat(f.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(f.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')')
  FROM pg_catalog.pg_language AS l
  CROSS JOIN pg_catalog.unnest(
         pg_catalog.array_append(pg_catalog.array_append(pg_catalog.array_append(
           '{}'::pg_catalog._oid, l.lanplcallfoid), l.laninline), l.lanvalidator))
         WITH ORDINALITY AS s
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) s.s)
 ORDER BY 1, 2, 7
