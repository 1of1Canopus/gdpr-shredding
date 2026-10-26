-- C-RC021-2e/-2h, statement 4: owner-context expressions (owner-context design page Rev 2,
-- rule O1). A foreign key whose action is CASCADE, SET NULL or SET DEFAULT writes its
-- referencing table (the FK-action target) as that table's owner, whoever wrote the
-- referenced row. Every expression the write evaluates then runs with the owner's rights.
-- Facts only: FunctionGrants decides which targets are owned outside reach and judges each
-- function by legs 1 to 7. An operator is given as its oprcode.
-- Rows, by kind:
--   tgt  one FK-action target: rel, its label, its owner.
--   chk  one table a foreign-key check queries (any action, either side): as tgt.
--   col  a column type of a target that may lead to a domain: rel, type.
--   edge a type that leads to another: rel is the type, type the next one. Domain to base
--        type, array to element, composite to attribute type, range to subtype, multirange
--        to range. Java follows them, so a domain inside an array or a composite is found.
--   fn   a function called by an expression on a table of a foreign key, or on a partitioned
--        ancestor: rel, the source's label, the slot (1-based, FunctionGrants.SLOTS "own"),
--        the function. Java keeps every slot of a tgt and the planner's slots of a chk.
--   dfn  a function called by a domain default or a domain CHECK: rel is the domain.
--   col and edge rows also come from every type an expression names (a domain it coerces to).
-- The functions are read from the stored expression trees, not from pg_depend (see below).
-- A trigger's own function is not in its tree (statement 3 judges it): only its WHEN is.
-- Each fn and dfn row also carries the function's label, its rights mode and, for a SECURITY
-- DEFINER function, whether reach may run it as itself, as statement 3 computes it (C-PR47-2,
-- C-PR47-4).
-- Binds, in text order (3): reach oids twice (_oid), the login oid.
-- The table filters are uncorrelated = ANY (subquery) filters, so the planner hashes each once: a
-- correlated EXISTS over conrelid OR confrelid scanned pg_constraint per row (0.9 s at 500
-- foreign-key tables).
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
SELECT x.kind, x.rel, x.label, x.owner, x.slot, x.typ, x.fn,
       -- The support key is read for aggregates only (statement 3); an O1 row never needs it.
       ''::pg_catalog.text AS fn_key,
       pg_catalog.concat(pg_catalog.quote_ident(fs.nspname), '.', pg_catalog.quote_ident(f.proname), '(',
                         pg_catalog.pg_get_function_identity_arguments(f.oid), ')') AS fn_label,
       f.prosecdef AS fn_definer,
       -- Read for a SECURITY DEFINER function only (leg 7); any other function gets true.
       (CASE WHEN NOT f.prosecdef THEN true
             ELSE ((CASE WHEN (f.proowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
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
                                           ELSE false END))) END) AS fn_reach,
       pg_catalog.pg_get_userbyid(x.owner)::pg_catalog.text AS owner_name
  FROM (SELECT DISTINCT u.kind, u.rel, u.label, u.owner, u.slot, u.typ, u.fn FROM (SELECT 'tgt'::pg_catalog.text AS kind, c.oid AS rel,
               c.oid::pg_catalog.regclass::pg_catalog.text AS label, c.relowner AS owner,
               0::pg_catalog.int4 AS slot, 0::pg_catalog.oid AS typ, 0::pg_catalog.oid AS fn
          FROM pg_catalog.pg_class AS c
         WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_constraint AS k
                        WHERE (k.conrelid OPERATOR(pg_catalog.=) c.oid)
                          AND (k.contype OPERATOR(pg_catalog.=) 'f')
                          AND ((k.confdeltype OPERATOR(pg_catalog.=) ANY ('{c,n,d}'::pg_catalog._char))
                               OR (k.confupdtype OPERATOR(pg_catalog.=) ANY ('{c,n,d}'::pg_catalog._char))))
        UNION ALL
        -- chk: a table some foreign-key check queries as its owner, any action, either side.
        -- The check writes nothing, but its query is planned as the owner, and planning folds
        -- an immutable call with constant arguments in the table's index expressions,
        -- predicates, partition key, and (constraint_exclusion = on, which any session may
        -- set) its CHECK constraints (measured on 16 and 17).
        SELECT 'chk', c.oid, c.oid::pg_catalog.regclass::pg_catalog.text, c.relowner, 0,
               0::pg_catalog.oid, 0::pg_catalog.oid
          FROM pg_catalog.pg_class AS c
         WHERE (c.oid OPERATOR(pg_catalog.=) ANY (SELECT k.conrelid FROM pg_catalog.pg_constraint AS k
                           WHERE (k.contype OPERATOR(pg_catalog.=) 'f')
                          UNION ALL
                          SELECT k.confrelid FROM pg_catalog.pg_constraint AS k
                           WHERE (k.contype OPERATOR(pg_catalog.=) 'f')))
        UNION ALL
        SELECT 'col', a.attrelid, '', 0::pg_catalog.oid, 0, a.atttypid, 0::pg_catalog.oid
          FROM pg_catalog.pg_attribute AS a
          JOIN pg_catalog.pg_type AS y ON (y.oid OPERATOR(pg_catalog.=) a.atttypid)
         WHERE (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped
           AND ((y.typtype OPERATOR(pg_catalog.=) ANY ('{d,c,r,m}'::pg_catalog._char))
                OR (y.typelem OPERATOR(pg_catalog.<>) 0::pg_catalog.oid))
           AND (a.attrelid OPERATOR(pg_catalog.=) ANY (SELECT k.conrelid FROM pg_catalog.pg_constraint AS k
                                 WHERE (k.contype OPERATOR(pg_catalog.=) 'f')
                                   AND ((k.confdeltype OPERATOR(pg_catalog.=) ANY ('{c,n,d}'::pg_catalog._char))
                                        OR (k.confupdtype OPERATOR(pg_catalog.=) ANY ('{c,n,d}'::pg_catalog._char)))))
        UNION ALL
        SELECT 'edge', y.oid, '', 0::pg_catalog.oid, 0, y.typbasetype, 0::pg_catalog.oid
          FROM pg_catalog.pg_type AS y
         WHERE (y.typtype OPERATOR(pg_catalog.=) 'd')
        UNION ALL
        SELECT 'edge', y.oid, '', 0::pg_catalog.oid, 0, y.typelem, 0::pg_catalog.oid
          FROM pg_catalog.pg_type AS y
          JOIN pg_catalog.pg_type AS z ON (z.oid OPERATOR(pg_catalog.=) y.typelem)
         WHERE (z.typtype OPERATOR(pg_catalog.=) ANY ('{d,c,r,m}'::pg_catalog._char))
            OR (z.typelem OPERATOR(pg_catalog.<>) 0::pg_catalog.oid)
        UNION ALL
        SELECT 'edge', y.oid, '', 0::pg_catalog.oid, 0, a.atttypid, 0::pg_catalog.oid
          FROM pg_catalog.pg_type AS y
          JOIN pg_catalog.pg_attribute AS a ON (a.attrelid OPERATOR(pg_catalog.=) y.typrelid)
          JOIN pg_catalog.pg_type AS z ON (z.oid OPERATOR(pg_catalog.=) a.atttypid)
         WHERE (y.typrelid OPERATOR(pg_catalog.<>) 0::pg_catalog.oid)
           AND (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped
           AND ((z.typtype OPERATOR(pg_catalog.=) ANY ('{d,c,r,m}'::pg_catalog._char))
                OR (z.typelem OPERATOR(pg_catalog.<>) 0::pg_catalog.oid))
        UNION ALL
        SELECT 'edge', r.rngtypid, '', 0::pg_catalog.oid, 0, r.rngsubtype, 0::pg_catalog.oid
          FROM pg_catalog.pg_range AS r
        UNION ALL
        SELECT 'edge', r.rngmultitypid, '', 0::pg_catalog.oid, 0, r.rngtypid, 0::pg_catalog.oid
          FROM pg_catalog.pg_range AS r
        UNION ALL
        -- Every function, operator and type an expression names, read from its stored tree.
        -- pg_depend is not used: it records no dependency on a pinned object, so a default over
        -- pg_read_file has no pg_depend row at all (measured on 16 and 17). Function oids are
        -- funcid, opfuncid, aggfnoid, winfnoid, tsmhandler, hashfuncid and negfuncid; operator
        -- oids (opno, eqop, sortop, the list of opnos, and a constraint's operator arrays) give
        -- their oprcode; a result type (resulttype, the field a CoerceToDomain node stores)
        -- gives a type row, so a domain the expression coerces to is followed like a column
        -- type. Column types themselves come from pg_attribute (col rows above).
        -- Sources on a target (fn and its types as col): defaults and generated columns (1, 2),
        -- table constraints of every kind with their operators (3), index expressions and
        -- predicates (4), the WHEN of BEFORE (5) and AFTER (6) triggers, rule qualifications
        -- and actions (7), the partition key of the target and of each partitioned ancestor
        -- (8). Sources on a domain (dfn and its types as edge): its default (9) and its CHECK
        -- constraints (10).
        SELECT (CASE WHEN (pg_catalog.right(pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 1), 4) OPERATOR(pg_catalog.=) 'type')
                     THEN (CASE WHEN (s.kind OPERATOR(pg_catalog.=) 'fn') THEN 'col' ELSE 'edge' END)
                     ELSE s.kind END),
               s.rel, s.label, 0::pg_catalog.oid, s.slot,
               (CASE WHEN (pg_catalog.right(pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 1), 4) OPERATOR(pg_catalog.=) 'type')
                     THEN pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 2)::pg_catalog.oid ELSE 0::pg_catalog.oid END),
               (CASE WHEN (pg_catalog.right(pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 1), 4) OPERATOR(pg_catalog.=) 'type')
                     THEN 0::pg_catalog.oid
                     WHEN (pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 1) OPERATOR(pg_catalog.=) ANY ('{opno,eqop,sortop}'::pg_catalog._text))
                     THEN (SELECT o.oprcode::pg_catalog.oid FROM pg_catalog.pg_operator AS o
                            WHERE (o.oid OPERATOR(pg_catalog.=) pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 2)::pg_catalog.oid))
                     ELSE pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 2)::pg_catalog.oid END)
          FROM (SELECT 'fn'::pg_catalog.text AS kind, ad.adrelid AS rel,
                       pg_catalog.concat('column ', pg_catalog.quote_ident(a.attname), ' of ',
                                         ad.adrelid::pg_catalog.regclass::pg_catalog.text) AS label,
                       (CASE WHEN (a.attgenerated OPERATOR(pg_catalog.=) 's') THEN 2 ELSE 1 END) AS slot,
                       ad.adbin::pg_catalog.text AS tree, '{}'::pg_catalog._oid AS ops
                  FROM pg_catalog.pg_attrdef AS ad
                  JOIN pg_catalog.pg_attribute AS a
                    ON (a.attrelid OPERATOR(pg_catalog.=) ad.adrelid)
                   AND (a.attnum OPERATOR(pg_catalog.=) ad.adnum)
                 WHERE (ad.adrelid OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                SELECT 'fn', k.conrelid,
                       pg_catalog.concat('constraint ', pg_catalog.quote_ident(k.conname), ' on ',
                                         k.conrelid::pg_catalog.regclass::pg_catalog.text), 3,
                       pg_catalog.concat(k.conbin::pg_catalog.text),
                       pg_catalog.array_cat(pg_catalog.array_cat(
                         k.conexclop::pg_catalog._oid,
                         k.conpfeqop::pg_catalog._oid),
                         pg_catalog.array_cat(
                         k.conppeqop::pg_catalog._oid,
                         k.conffeqop::pg_catalog._oid))
                  FROM pg_catalog.pg_constraint AS k
                 WHERE (k.conrelid OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                SELECT 'fn', i.indrelid,
                       pg_catalog.concat('index ', i.indexrelid::pg_catalog.regclass::pg_catalog.text), 4,
                       pg_catalog.concat(i.indexprs::pg_catalog.text, ' ', i.indpred::pg_catalog.text),
                       '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_index AS i
                 WHERE (i.indrelid OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                SELECT 'fn', t.tgrelid,
                       pg_catalog.concat('trigger ', pg_catalog.quote_ident(t.tgname), ' on ',
                                         t.tgrelid::pg_catalog.regclass::pg_catalog.text),
                       (CASE WHEN ((t.tgtype::pg_catalog.int4 OPERATOR(pg_catalog.&) 2)
                                   OPERATOR(pg_catalog.<>) 0) THEN 5 ELSE 6 END),
                       pg_catalog.concat(t.tgqual::pg_catalog.text), '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_trigger AS t
                 WHERE (t.tgrelid OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                SELECT 'fn', r.ev_class,
                       pg_catalog.concat('rule ', pg_catalog.quote_ident(r.rulename), ' on ',
                                         r.ev_class::pg_catalog.regclass::pg_catalog.text), 7,
                       pg_catalog.concat(r.ev_qual::pg_catalog.text, ' ', r.ev_action::pg_catalog.text),
                       '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_rewrite AS r
                 WHERE (r.ev_class OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                -- The ancestors function returns the relation itself first, and nothing for a
                -- table outside any partition tree.
                SELECT 'fn', c.oid,
                       pg_catalog.concat('table ', an.relid::pg_catalog.text), 8,
                       pg_catalog.concat(pt.partexprs::pg_catalog.text), '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_class AS c
                  CROSS JOIN pg_catalog.pg_partition_ancestors(c.oid) AS an
                  JOIN pg_catalog.pg_partitioned_table AS pt
                    ON (pt.partrelid OPERATOR(pg_catalog.=) an.relid)
                 WHERE (c.relispartition OR (c.relkind OPERATOR(pg_catalog.=) 'p'))
                   AND (c.oid OPERATOR(pg_catalog.=) ANY (SELECT fk.conrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')
                                 UNION ALL
                                 SELECT fk.confrelid FROM pg_catalog.pg_constraint AS fk
                                  WHERE (fk.contype OPERATOR(pg_catalog.=) 'f')))
                UNION ALL
                SELECT 'dfn', y.oid, pg_catalog.concat('domain ', y.oid::pg_catalog.regtype::pg_catalog.text),
                       9, pg_catalog.concat(y.typdefaultbin::pg_catalog.text), '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_type AS y
                 WHERE (y.typtype OPERATOR(pg_catalog.=) 'd')
                UNION ALL
                SELECT 'dfn', k.contypid,
                       pg_catalog.concat('constraint ', pg_catalog.quote_ident(k.conname), ' on domain ',
                                         k.contypid::pg_catalog.regtype::pg_catalog.text), 10,
                       pg_catalog.concat(k.conbin::pg_catalog.text), '{}'::pg_catalog._oid
                  FROM pg_catalog.pg_constraint AS k
                 WHERE (k.contypid OPERATOR(pg_catalog.<>) 0::pg_catalog.oid)) AS s
          -- One string per source: the tree, each listed opno of a row comparison, each
          -- operator of the constraint's arrays, each written as ":opno N". A function in FROM
          -- that returns a base type names its one column after its alias (lt.lt, mt.mt).
          CROSS JOIN pg_catalog.regexp_matches(
                 pg_catalog.concat(s.tree, ' ',
                   pg_catalog.regexp_replace(
                     pg_catalog.array_to_string(ARRAY(
                       SELECT pg_catalog.array_to_string(lt.lt, ' ') FROM pg_catalog.regexp_matches(s.tree, ':opnos \(o ([0-9 ]+)\)', 'g') AS lt),
                       ' '), '([0-9]+)', ':opno \1', 'g'), ' ',
                   pg_catalog.regexp_replace(pg_catalog.array_to_string(s.ops, ' '),
                                             '([0-9]+)', ':opno \1', 'g')),
                 ':(funcid|opfuncid|aggfnoid|winfnoid|tsmhandler|hashfuncid|negfuncid|opno|eqop|sortop|resulttype) ([0-9]+)',
                 'g') AS mt
         WHERE (pg_catalog.split_part(pg_catalog.array_to_string(mt.mt, ' '), ' ', 2) OPERATOR(pg_catalog.<>) '0')
) AS u) AS x
  LEFT JOIN pg_catalog.pg_proc AS f ON (f.oid OPERATOR(pg_catalog.=) x.fn)
  LEFT JOIN pg_catalog.pg_namespace AS fs ON (fs.oid OPERATOR(pg_catalog.=) f.pronamespace)
  CROSS JOIN (SELECT ?::pg_catalog.oid AS login) AS me
 ORDER BY 1, 2, 5, 3, 7
