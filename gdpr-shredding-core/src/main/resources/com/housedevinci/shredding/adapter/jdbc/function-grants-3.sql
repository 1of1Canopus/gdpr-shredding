-- C-PR45-3, statement 3: caller objects (design revision 5, rule R6). One row per (object,
-- slot, support function): a catalogue row that names a function the server calls for you.
-- Aggregates (eight slots), operators (code, restrict, join), languages (handler, inline,
-- validator), and the no-check slots of C-RC021-2 (triggers, event triggers, types, ranges,
-- operator family support, access methods, text search parsers and templates, foreign-data
-- wrappers, conversions, transforms, planner support). The slot is the 1-based position in the
-- kind's list; FunctionGrants names it.
-- Facts only: Java decides which slots run with the owner's rights, or with no EXECUTE
-- check, and judges their functions (FunctionGrants).
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
-- Each row also carries three facts on its slot function (C-PR47-2): its schema-qualified
-- name (a support key in the manifest has no schema, so this is what tells evil.f(x) from
-- public.f(x)), its rights mode, and whether reach may run it as itself: PUBLIC holds EXECUTE
-- on it, or a role whose rights the login may use (inherited, or reachable by SET ROLE) holds
-- EXECUTE on it or owns it (then its body runs with rights the login has anyway). Membership
-- alone is not enough (C-PR47-4): a PostgreSQL 16 grant WITH INHERIT FALSE, SET FALSE gives the
-- login none of the role's rights. The refusing legs keep reach as it is. CASE, not OR, so that
-- oid 0 (PUBLIC) never reaches pg_has_role. Labels are quoted (C-PR47-5): a name that is not
-- plain lowercase shows in quotes, as regprocedure prints it.
-- Binds, in text order (14): aggregate usable, aggregate slot owner and grantee (reach oids,
-- _oid), aggregate login (oid); operator slot owner and grantee, operator login; language
-- usable, language slot owner and grantee, language login; no-check slot owner and grantee,
-- no-check login.
SELECT 'agg'::pg_catalog.text AS kind,
       p.oid AS oid,
       pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.proname), '(',
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
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')') AS fn_key,
       pg_catalog.concat(pg_catalog.quote_ident(fs.nspname), '.', pg_catalog.quote_ident(f.proname), '(',
                         pg_catalog.pg_get_function_identity_arguments(f.oid), ')') AS fn_label,
       f.prosecdef AS fn_definer,
       ((CASE WHEN (f.proowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
              THEN (pg_catalog.pg_has_role(me.login, f.proowner, 'USAGE')
                    OR pg_catalog.pg_has_role(me.login, f.proowner, 'SET'))
              ELSE false END)
        OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(CASE WHEN f.proacl IS NULL
                                                         THEN pg_catalog.acldefault('f', f.proowner)
                                                         ELSE f.proacl END) AS h
                    WHERE (h.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
                      AND (CASE WHEN (h.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid) THEN true
                                WHEN (h.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
                                THEN (pg_catalog.pg_has_role(me.login, h.grantee, 'USAGE')
                                      OR pg_catalog.pg_has_role(me.login, h.grantee, 'SET'))
                                ELSE false END))) AS fn_reach
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
  JOIN pg_catalog.pg_namespace AS fs ON (fs.oid OPERATOR(pg_catalog.=) f.pronamespace)
  CROSS JOIN (SELECT ?::pg_catalog.oid AS login) AS me
UNION ALL
-- Operators have no ACL: anyone who can name one can use it.
SELECT 'opr', o.oid, o.oid::pg_catalog.regoperator::pg_catalog.text, o.oprowner,
       pg_catalog.pg_get_userbyid(o.oprowner)::pg_catalog.text, true, s.ordinality, f.oid,
       pg_catalog.concat(f.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(f.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')'),
       pg_catalog.concat(pg_catalog.quote_ident(fs.nspname), '.', pg_catalog.quote_ident(f.proname), '(',
                         pg_catalog.pg_get_function_identity_arguments(f.oid), ')'),
       f.prosecdef,
       ((CASE WHEN (f.proowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
              THEN (pg_catalog.pg_has_role(me.login, f.proowner, 'USAGE')
                    OR pg_catalog.pg_has_role(me.login, f.proowner, 'SET'))
              ELSE false END)
        OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(CASE WHEN f.proacl IS NULL
                                                         THEN pg_catalog.acldefault('f', f.proowner)
                                                         ELSE f.proacl END) AS h
                    WHERE (h.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
                      AND (CASE WHEN (h.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid) THEN true
                                WHEN (h.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
                                THEN (pg_catalog.pg_has_role(me.login, h.grantee, 'USAGE')
                                      OR pg_catalog.pg_has_role(me.login, h.grantee, 'SET'))
                                ELSE false END)))
  FROM pg_catalog.pg_operator AS o
  CROSS JOIN pg_catalog.unnest(
         pg_catalog.array_append(pg_catalog.array_append(pg_catalog.array_append(
           '{}'::pg_catalog._oid, o.oprcode::pg_catalog.oid), o.oprrest::pg_catalog.oid),
           o.oprjoin::pg_catalog.oid)) WITH ORDINALITY AS s
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) s.s)
  JOIN pg_catalog.pg_namespace AS fs ON (fs.oid OPERATOR(pg_catalog.=) f.pronamespace)
  CROSS JOIN (SELECT ?::pg_catalog.oid AS login) AS me
UNION ALL
-- A language is usable by a role that is not a superuser only when it is trusted.
SELECT 'lang', l.oid, pg_catalog.quote_ident(l.lanname), l.lanowner,
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
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')'),
       pg_catalog.concat(pg_catalog.quote_ident(fs.nspname), '.', pg_catalog.quote_ident(f.proname), '(',
                         pg_catalog.pg_get_function_identity_arguments(f.oid), ')'),
       f.prosecdef,
       ((CASE WHEN (f.proowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
              THEN (pg_catalog.pg_has_role(me.login, f.proowner, 'USAGE')
                    OR pg_catalog.pg_has_role(me.login, f.proowner, 'SET'))
              ELSE false END)
        OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(CASE WHEN f.proacl IS NULL
                                                         THEN pg_catalog.acldefault('f', f.proowner)
                                                         ELSE f.proacl END) AS h
                    WHERE (h.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
                      AND (CASE WHEN (h.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid) THEN true
                                WHEN (h.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
                                THEN (pg_catalog.pg_has_role(me.login, h.grantee, 'USAGE')
                                      OR pg_catalog.pg_has_role(me.login, h.grantee, 'SET'))
                                ELSE false END)))
  FROM pg_catalog.pg_language AS l
  CROSS JOIN pg_catalog.unnest(
         pg_catalog.array_append(pg_catalog.array_append(pg_catalog.array_append(
           '{}'::pg_catalog._oid, l.lanplcallfoid), l.laninline), l.lanvalidator))
         WITH ORDINALITY AS s
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) s.s)
  JOIN pg_catalog.pg_namespace AS fs ON (fs.oid OPERATOR(pg_catalog.=) f.pronamespace)
  CROSS JOIN (SELECT ?::pg_catalog.oid AS login) AS me
UNION ALL
-- C-RC021-2, no-check slots (trigger-slots addendum Rev 2): the server calls these functions
-- with no EXECUTE check, whoever runs the statement. Every row of the database is read, whatever
-- its table, its state (tgenabled, evtenabled) or its owner. An object with no owner column is
-- given the bootstrap superuser (oid 10). Kept only when the verdict can refuse the function
-- (ruling 8): native, a shipped record, core (oid below 16384), or SECURITY DEFINER. An
-- extension member needs no clause of its own (C-PR51-2): the verdict judges a member only when
-- it is native, an aggregate (language internal) or SECURITY DEFINER, and a clause above keeps
-- each of those; a non-native invoker member runs as the caller and always passes. Labels are
-- built inside the pinned window, so regclass and regtype print
-- the schema of every relation and type outside pg_catalog.
SELECT x.kind, x.oid, x.label, x.owner, pg_catalog.pg_get_userbyid(x.owner)::pg_catalog.text, true,
       x.slot, f.oid,
       pg_catalog.concat(f.proname, '(',
         (SELECT pg_catalog.string_agg(t.typname::pg_catalog.text, ',' ORDER BY arg.ordinality)
            FROM pg_catalog.unnest(f.proargtypes::pg_catalog._oid) WITH ORDINALITY AS arg
            JOIN pg_catalog.pg_type AS t ON (t.oid OPERATOR(pg_catalog.=) arg.arg)), ')'),
       pg_catalog.concat(pg_catalog.quote_ident(fs.nspname), '.', pg_catalog.quote_ident(f.proname), '(',
                         pg_catalog.pg_get_function_identity_arguments(f.oid), ')'),
       f.prosecdef,
       ((CASE WHEN (f.proowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
              THEN (pg_catalog.pg_has_role(me.login, f.proowner, 'USAGE')
                    OR pg_catalog.pg_has_role(me.login, f.proowner, 'SET'))
              ELSE false END)
        OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(CASE WHEN f.proacl IS NULL
                                                         THEN pg_catalog.acldefault('f', f.proowner)
                                                         ELSE f.proacl END) AS h
                    WHERE (h.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE')
                      AND (CASE WHEN (h.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid) THEN true
                                WHEN (h.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
                                THEN (pg_catalog.pg_has_role(me.login, h.grantee, 'USAGE')
                                      OR pg_catalog.pg_has_role(me.login, h.grantee, 'SET'))
                                ELSE false END)))
  FROM (SELECT 'trg'::pg_catalog.text AS kind, t.oid AS oid,
               pg_catalog.concat(pg_catalog.quote_ident(t.tgname), ' on ',
                                 t.tgrelid::pg_catalog.regclass::pg_catalog.text) AS label,
               c.relowner AS owner, 1::pg_catalog.int8 AS slot, t.tgfoid AS fn
          FROM pg_catalog.pg_trigger AS t
          JOIN pg_catalog.pg_class AS c ON (c.oid OPERATOR(pg_catalog.=) t.tgrelid)
        UNION ALL
        SELECT 'evt', e.oid, pg_catalog.concat(pg_catalog.quote_ident(e.evtname), ' on ', e.evtevent),
               e.evtowner, 1, e.evtfoid
          FROM pg_catalog.pg_event_trigger AS e
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 1,
               y.typinput::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 2,
               y.typoutput::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 3,
               y.typreceive::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 4,
               y.typsend::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 5,
               y.typmodin::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 6,
               y.typmodout::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 7,
               y.typanalyze::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'typ', y.oid, y.oid::pg_catalog.regtype::pg_catalog.text, y.typowner, 8,
               y.typsubscript::pg_catalog.oid FROM pg_catalog.pg_type AS y
        UNION ALL
        SELECT 'rng', r.rngtypid, r.rngtypid::pg_catalog.regtype::pg_catalog.text, y.typowner, 1,
               r.rngcanonical::pg_catalog.oid FROM pg_catalog.pg_range AS r
          JOIN pg_catalog.pg_type AS y ON (y.oid OPERATOR(pg_catalog.=) r.rngtypid)
        UNION ALL
        SELECT 'rng', r.rngtypid, r.rngtypid::pg_catalog.regtype::pg_catalog.text, y.typowner, 2,
               r.rngsubdiff::pg_catalog.oid FROM pg_catalog.pg_range AS r
          JOIN pg_catalog.pg_type AS y ON (y.oid OPERATOR(pg_catalog.=) r.rngtypid)
        UNION ALL
        SELECT 'amp', a.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(o.opfname)),
               o.opfowner, 1, a.amproc::pg_catalog.oid FROM pg_catalog.pg_amproc AS a
          JOIN pg_catalog.pg_opfamily AS o ON (o.oid OPERATOR(pg_catalog.=) a.amprocfamily)
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) o.opfnamespace)
        UNION ALL
        SELECT 'am', m.oid, pg_catalog.quote_ident(m.amname), 10::pg_catalog.oid, 1,
               m.amhandler::pg_catalog.oid FROM pg_catalog.pg_am AS m
        UNION ALL
        SELECT 'tsp', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.prsname)),
               10::pg_catalog.oid, 1, p.prsstart::pg_catalog.oid FROM pg_catalog.pg_ts_parser AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.prsnamespace)
        UNION ALL
        SELECT 'tsp', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.prsname)),
               10::pg_catalog.oid, 2, p.prstoken::pg_catalog.oid FROM pg_catalog.pg_ts_parser AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.prsnamespace)
        UNION ALL
        SELECT 'tsp', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.prsname)),
               10::pg_catalog.oid, 3, p.prsend::pg_catalog.oid FROM pg_catalog.pg_ts_parser AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.prsnamespace)
        UNION ALL
        SELECT 'tsp', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.prsname)),
               10::pg_catalog.oid, 4, p.prsheadline::pg_catalog.oid FROM pg_catalog.pg_ts_parser AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.prsnamespace)
        UNION ALL
        SELECT 'tsp', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.prsname)),
               10::pg_catalog.oid, 5, p.prslextype::pg_catalog.oid FROM pg_catalog.pg_ts_parser AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.prsnamespace)
        UNION ALL
        SELECT 'tst', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.tmplname)),
               10::pg_catalog.oid, 1, p.tmplinit::pg_catalog.oid FROM pg_catalog.pg_ts_template AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.tmplnamespace)
        UNION ALL
        SELECT 'tst', p.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(p.tmplname)),
               10::pg_catalog.oid, 2, p.tmpllexize::pg_catalog.oid FROM pg_catalog.pg_ts_template AS p
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) p.tmplnamespace)
        UNION ALL
        SELECT 'fdw', w.oid, pg_catalog.quote_ident(w.fdwname), w.fdwowner, 1, w.fdwhandler
          FROM pg_catalog.pg_foreign_data_wrapper AS w
        UNION ALL
        SELECT 'fdw', w.oid, pg_catalog.quote_ident(w.fdwname), w.fdwowner, 2, w.fdwvalidator
          FROM pg_catalog.pg_foreign_data_wrapper AS w
        UNION ALL
        SELECT 'cnv', v.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(v.conname)),
               v.conowner, 1, v.conproc::pg_catalog.oid FROM pg_catalog.pg_conversion AS v
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) v.connamespace)
        UNION ALL
        SELECT 'trf', r.oid,
               pg_catalog.concat(r.trftype::pg_catalog.regtype::pg_catalog.text, ' for language ',
                                 pg_catalog.quote_ident(l.lanname)),
               10::pg_catalog.oid, 1, r.trffromsql::pg_catalog.oid FROM pg_catalog.pg_transform AS r
          JOIN pg_catalog.pg_language AS l ON (l.oid OPERATOR(pg_catalog.=) r.trflang)
        UNION ALL
        SELECT 'trf', r.oid,
               pg_catalog.concat(r.trftype::pg_catalog.regtype::pg_catalog.text, ' for language ',
                                 pg_catalog.quote_ident(l.lanname)),
               10::pg_catalog.oid, 2, r.trftosql::pg_catalog.oid FROM pg_catalog.pg_transform AS r
          JOIN pg_catalog.pg_language AS l ON (l.oid OPERATOR(pg_catalog.=) r.trflang)
        UNION ALL
        SELECT 'sup', q.oid,
               pg_catalog.concat(pg_catalog.quote_ident(n.nspname), '.', pg_catalog.quote_ident(q.proname), '(',
                                 pg_catalog.pg_get_function_identity_arguments(q.oid), ')'),
               q.proowner, 1, q.prosupport::pg_catalog.oid FROM pg_catalog.pg_proc AS q
          JOIN pg_catalog.pg_namespace AS n ON (n.oid OPERATOR(pg_catalog.=) q.pronamespace)) AS x
  -- An empty slot is oid 0, which no function has: the join drops it.
  JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) x.fn)
  JOIN pg_catalog.pg_namespace AS fs ON (fs.oid OPERATOR(pg_catalog.=) f.pronamespace)
  JOIN pg_catalog.pg_language AS fl ON (fl.oid OPERATOR(pg_catalog.=) f.prolang)
  CROSS JOIN (SELECT ?::pg_catalog.oid AS login) AS me
 WHERE (fl.lanname OPERATOR(pg_catalog.=) ANY ('{internal,c}'::pg_catalog._name))
    OR (f.oid OPERATOR(pg_catalog.<) 16384::pg_catalog.oid)
    OR f.prosecdef
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_init_privs AS i
                WHERE (i.objoid OPERATOR(pg_catalog.=) f.oid)
                  AND (i.classoid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass)
                  AND (i.objsubid OPERATOR(pg_catalog.=) 0))
 ORDER BY 1, 2, 7
