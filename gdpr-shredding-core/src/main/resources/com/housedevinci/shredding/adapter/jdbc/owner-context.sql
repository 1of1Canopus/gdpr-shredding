-- C-RC021-2c/-2f/-2g: owner-context facts for checkRole (owner-context design page Rev 2,
-- rules O2 and O3). Facts only: OwnerContext decides which owners are outside reach, whether
-- O2 applies, and what refuses.
-- Rows, by kind (oid, label, owner, other):
--   def  a SECURITY DEFINER function or procedure, any language, any ACL: owner its owner.
--   fk   a foreign key, any action: owner the referencing table's owner, other the
--        referenced table's owner.
--   nsp  a schema: owner its owner.
--   crt  a CREATE grant on a schema to a role in reach or to PUBLIC: other the grantee.
--   own  an object of this database, other than a schema, owned by a role in reach
--        (pg_shdepend, deptype o): label as the server describes it, owner the role.
--   mnt  a MAINTAIN grant on a relation to a role in reach or to PUBLIC: owner the relation's
--        owner, other the grantee.
--   trg  a TRIGGER grant on a relation to a role in reach or to PUBLIC (C-PR53-1): as mnt.
--   ptn  a partitioned table or index owned by a role in reach, with a partition (any depth)
--        of another owner (C-PR53-3): oid the parent, label "parent<TAB>partition", owner the
--        parent's owner, owner_name the partition owner's name, other the partition's owner.
-- Binds, in text order (5): reach oids (_oid), five times.
-- Runs inside the gate's pinned window. House dialect: every name qualified, no CTE.
SELECT 'def'::pg_catalog.text AS kind, p.oid AS oid,
       p.oid::pg_catalog.regprocedure::pg_catalog.text AS label, p.proowner AS owner,
       pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text AS owner_name,
       0::pg_catalog.oid AS other
  FROM pg_catalog.pg_proc AS p
 WHERE p.prosecdef
UNION ALL
SELECT 'fk', k.oid,
       pg_catalog.concat('foreign key ', pg_catalog.quote_ident(k.conname), ' on ',
                         k.conrelid::pg_catalog.regclass::pg_catalog.text, ' referencing ',
                         k.confrelid::pg_catalog.regclass::pg_catalog.text),
       c.relowner, pg_catalog.pg_get_userbyid(c.relowner)::pg_catalog.text, r.relowner
  FROM pg_catalog.pg_constraint AS k
  JOIN pg_catalog.pg_class AS c ON (c.oid OPERATOR(pg_catalog.=) k.conrelid)
  JOIN pg_catalog.pg_class AS r ON (r.oid OPERATOR(pg_catalog.=) k.confrelid)
 WHERE (k.contype OPERATOR(pg_catalog.=) 'f')
UNION ALL
SELECT 'nsp', n.oid, pg_catalog.quote_ident(n.nspname), n.nspowner,
       pg_catalog.pg_get_userbyid(n.nspowner)::pg_catalog.text, 0::pg_catalog.oid
  FROM pg_catalog.pg_namespace AS n
UNION ALL
SELECT 'crt', n.oid, pg_catalog.quote_ident(n.nspname), n.nspowner,
       pg_catalog.pg_get_userbyid(n.nspowner)::pg_catalog.text, g.grantee
  FROM pg_catalog.pg_namespace AS n
  CROSS JOIN pg_catalog.aclexplode(CASE WHEN n.nspacl IS NULL
                                        THEN pg_catalog.acldefault('n', n.nspowner)
                                        ELSE n.nspacl END) AS g
 WHERE (g.privilege_type OPERATOR(pg_catalog.=) 'CREATE')
   AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
        OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid)))
UNION ALL
SELECT 'own', s.objid, pg_catalog.pg_describe_object(s.classid, s.objid, s.objsubid), s.refobjid,
       pg_catalog.pg_get_userbyid(s.refobjid)::pg_catalog.text, s.classid
  FROM pg_catalog.pg_shdepend AS s
 WHERE (s.deptype OPERATOR(pg_catalog.=) 'o')
   AND (s.dbid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database AS d
                                        WHERE (d.datname OPERATOR(pg_catalog.=)
                                               pg_catalog.current_database())))
   AND (s.classid OPERATOR(pg_catalog.<>) 'pg_catalog.pg_namespace'::pg_catalog.regclass)
   AND (s.refobjid OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
UNION ALL
SELECT 'mnt', c.oid, c.oid::pg_catalog.regclass::pg_catalog.text, c.relowner,
       pg_catalog.pg_get_userbyid(c.relowner)::pg_catalog.text, g.grantee
  FROM pg_catalog.pg_class AS c
  CROSS JOIN pg_catalog.aclexplode(c.relacl) AS g
 WHERE (c.relacl IS NOT NULL)
   AND (g.privilege_type OPERATOR(pg_catalog.=) 'MAINTAIN')
   AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
        OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid)))
UNION ALL
SELECT 'trg', c.oid, c.oid::pg_catalog.regclass::pg_catalog.text, c.relowner,
       pg_catalog.pg_get_userbyid(c.relowner)::pg_catalog.text, g.grantee
  FROM pg_catalog.pg_class AS c
  CROSS JOIN pg_catalog.aclexplode(c.relacl) AS g
 WHERE (c.relacl IS NOT NULL)
   AND (g.privilege_type OPERATOR(pg_catalog.=) 'TRIGGER')
   AND ((g.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
        OR (g.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid)))
UNION ALL
SELECT 'ptn', c.oid,
       pg_catalog.concat(c.oid::pg_catalog.regclass::pg_catalog.text, pg_catalog.chr(9),
                         t.relid::pg_catalog.regclass::pg_catalog.text),
       c.relowner, pg_catalog.pg_get_userbyid(d.relowner)::pg_catalog.text, d.relowner
  FROM pg_catalog.pg_class AS c
  CROSS JOIN pg_catalog.pg_partition_tree(c.oid) AS t
  JOIN pg_catalog.pg_class AS d ON (d.oid OPERATOR(pg_catalog.=) t.relid)
 WHERE (c.relkind OPERATOR(pg_catalog.=) ANY ('{p,I}'::pg_catalog._char))
   AND (c.relowner OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))
   AND (d.relowner OPERATOR(pg_catalog.<>) c.relowner)
 ORDER BY 1, 3, 2, 6
