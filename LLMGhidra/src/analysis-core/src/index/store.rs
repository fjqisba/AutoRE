// SPDX-License-Identifier: Apache-2.0
//! 可重建的分析缓存。原始文件和原生 Program 数据库仍是各自的权威数据源。
use super::*;
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;

// 翻转符号位，使 SQLite 的有符号 INTEGER 排序与 ELF u64 地址顺序相同。
pub fn key(address: u64) -> i64 {
    (address ^ (1 << 63)) as i64
}
fn address(key: i64) -> u64 {
    (key as u64) ^ (1 << 63)
}
fn err(e: rusqlite::Error) -> String {
    e.to_string()
}

pub struct Store {
    pub(crate) db: Connection,
}
impl Store {
    pub fn create(path: &Path) -> Result<Self> {
        let db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-8192;
          CREATE TABLE IF NOT EXISTS functions(address INTEGER PRIMARY KEY,name TEXT NOT NULL,size INTEGER NOT NULL,source TEXT NOT NULL,confidence INTEGER NOT NULL,search TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS aliases(address INTEGER NOT NULL,name TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(address,name,source));
          CREATE INDEX IF NOT EXISTS alias_name ON aliases(name);
          CREATE TABLE IF NOT EXISTS ranges(start INTEGER NOT NULL,end INTEGER NOT NULL,entry INTEGER NOT NULL,source TEXT NOT NULL,PRIMARY KEY(start,end,entry,source));
          CREATE INDEX IF NOT EXISTS range_end ON ranges(end);
          CREATE TABLE IF NOT EXISTS xrefs(src INTEGER NOT NULL,dst INTEGER NOT NULL,kind TEXT NOT NULL,confidence INTEGER NOT NULL,evidence TEXT NOT NULL,PRIMARY KEY(src,dst,kind));
          CREATE INDEX IF NOT EXISTS xrefs_to ON xrefs(dst,src);
          CREATE TABLE IF NOT EXISTS strings(address INTEGER NOT NULL,end INTEGER NOT NULL,encoding TEXT NOT NULL,text TEXT NOT NULL,truncated INTEGER NOT NULL,source TEXT NOT NULL,PRIMARY KEY(address,encoding));
          CREATE TABLE IF NOT EXISTS symbols(address INTEGER NOT NULL,name TEXT NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(address,name,kind));
          CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,state TEXT NOT NULL,bytes INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS unresolved(site INTEGER PRIMARY KEY,evidence TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS stats(id INTEGER PRIMARY KEY,f INTEGER NOT NULL,x INTEGER NOT NULL,s INTEGER NOT NULL,i INTEGER NOT NULL,e INTEGER NOT NULL,c INTEGER NOT NULL,u INTEGER NOT NULL);
          INSERT OR IGNORE INTO stats VALUES(1,0,0,0,0,0,0,0);
          CREATE TRIGGER IF NOT EXISTS count_f AFTER INSERT ON functions BEGIN UPDATE stats SET f=f+1,c=c+(new.confidence<=1) WHERE id=1; END;
          CREATE TRIGGER IF NOT EXISTS upgrade_f AFTER UPDATE OF confidence ON functions WHEN old.confidence<=1 AND new.confidence>1 BEGIN UPDATE stats SET c=c-1 WHERE id=1; END;
          CREATE TRIGGER IF NOT EXISTS count_u AFTER INSERT ON unresolved BEGIN UPDATE stats SET u=u+1 WHERE id=1; END;
          CREATE TRIGGER IF NOT EXISTS count_x AFTER INSERT ON xrefs BEGIN UPDATE stats SET x=x+1 WHERE id=1; END;
          CREATE TRIGGER IF NOT EXISTS count_s AFTER INSERT ON strings BEGIN UPDATE stats SET s=s+1 WHERE id=1; END;
          CREATE TRIGGER IF NOT EXISTS count_sym AFTER INSERT ON symbols BEGIN UPDATE stats SET i=i+(new.kind='import'),e=e+(new.kind='export') WHERE id=1; END;") .map_err(err)?;
        Ok(Self { db })
    }
    pub fn read(path: &Path) -> Result<Self> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(err)?;
        db.busy_timeout(std::time::Duration::from_millis(100))
            .map_err(err)?;
        Ok(Self { db })
    }
    pub fn metadata(&self, name: &str, value: &str) -> Result<()> {
        self.db
            .execute(
                "INSERT OR REPLACE INTO metadata VALUES(?1,?2)",
                params![name, value],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn begin_snapshot(&self) -> Result<()> {
        self.db.execute_batch("BEGIN DEFERRED").map_err(err)
    }
    pub fn metadata_value(&self, name: &str) -> Result<String> {
        self.db
            .query_row("SELECT value FROM metadata WHERE key=?1", [name], |r| {
                r.get(0)
            })
            .map_err(err)
    }
    pub fn task_done(&self, id: &str) -> bool {
        self.db
            .query_row(
                "SELECT state='complete' FROM tasks WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }
    pub(crate) fn commit(&mut self, batch: &FactBatch) -> Result<()> {
        let tx = self.db.transaction().map_err(err)?;
        {
            let mut f = tx.prepare_cached("INSERT INTO functions VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(address) DO UPDATE SET name=CASE WHEN excluded.confidence>functions.confidence THEN excluded.name ELSE functions.name END,size=CASE WHEN functions.size=0 THEN excluded.size ELSE functions.size END,source=CASE WHEN excluded.confidence>functions.confidence THEN excluded.source ELSE functions.source END,confidence=max(functions.confidence,excluded.confidence)").map_err(err)?;
            let mut alias = tx
                .prepare_cached("INSERT OR IGNORE INTO aliases VALUES(?1,?2,?3)")
                .map_err(err)?;
            let mut range = tx
                .prepare_cached("INSERT OR IGNORE INTO ranges VALUES(?1,?2,?3,?4)")
                .map_err(err)?;
            for item in &batch.functions {
                f.execute(params![
                    key(item.address),
                    item.name,
                    item.size as i64,
                    item.source,
                    item.confidence,
                    format!("{:x}", item.address)
                ])
                .map_err(err)?;
                alias
                    .execute(params![key(item.address), item.name, item.source])
                    .map_err(err)?;
                if item.size > 0 {
                    if let Some(end) = item.address.checked_add(item.size) {
                        range
                            .execute(params![
                                key(item.address),
                                key(end),
                                key(item.address),
                                item.source
                            ])
                            .map_err(err)?;
                    }
                }
            }
            let mut x = tx.prepare_cached("INSERT INTO xrefs VALUES(?1,?2,?3,?4,?5) ON CONFLICT(src,dst,kind) DO UPDATE SET confidence=max(xrefs.confidence,excluded.confidence),evidence=CASE WHEN excluded.confidence>xrefs.confidence THEN excluded.evidence ELSE xrefs.evidence END").map_err(err)?;
            let mut unknown=tx.prepare_cached("INSERT INTO unresolved VALUES(?1,?2) ON CONFLICT(site) DO UPDATE SET evidence=excluded.evidence").map_err(err)?;
            for item in &batch.xrefs {
                if item.kind == "unresolved-indirect" {
                    unknown
                        .execute(params![key(item.from), item.evidence])
                        .map_err(err)?;
                    continue;
                }
                x.execute(params![
                    key(item.from),
                    key(item.to),
                    item.kind,
                    item.confidence,
                    item.evidence
                ])
                .map_err(err)?;
            }
            let mut s = tx
                .prepare_cached("INSERT INTO strings VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(address,encoding) DO UPDATE SET end=excluded.end,text=excluded.text,truncated=excluded.truncated,source=excluded.source")
                .map_err(err)?;
            for item in &batch.strings {
                s.execute(params![
                    key(item.address),
                    key(item.end),
                    item.encoding,
                    item.text,
                    item.truncated,
                    item.source
                ])
                .map_err(err)?;
            }
            let mut sym = tx
                .prepare_cached("INSERT OR IGNORE INTO symbols VALUES(?1,?2,?3,?4)")
                .map_err(err)?;
            for item in &batch.symbols {
                sym.execute(params![
                    key(item.address),
                    item.name,
                    item.kind,
                    item.source
                ])
                .map_err(err)?;
            }
        }
        if let Some((id, bytes)) = &batch.checkpoint {
            tx.execute(
                "INSERT OR REPLACE INTO tasks VALUES(?1,?2,?3)",
                params![
                    id,
                    if batch.warnings.is_empty() {
                        "complete"
                    } else {
                        "partial"
                    },
                    *bytes as i64
                ],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
    pub fn counts(&self) -> Result<Counts> {
        self.db
            .query_row("SELECT f,x,s,i,e,c,u FROM stats WHERE id=1", [], |r| {
                Ok(Counts {
                    functions: r.get(0)?,
                    xrefs: r.get(1)?,
                    strings: r.get(2)?,
                    imports: r.get(3)?,
                    exports: r.get(4)?,
                    candidates: r.get(5)?,
                    unresolved: r.get(6)?,
                })
            })
            .map_err(err)
    }
    /// 页内条数有上限；查询运行在交互 worker，不在 egui 帧线程中。
    pub fn functions(
        &self,
        query: &str,
        after: Option<u64>,
        count: usize,
    ) -> Result<Vec<FunctionFact>> {
        let mut statement = self.db.prepare("SELECT address,name,size,source,confidence FROM functions f WHERE (?1='' OR instr(lower(name),lower(?1))>0 OR instr(search,lower(?1))>0 OR EXISTS(SELECT 1 FROM aliases a WHERE a.address=f.address AND instr(lower(a.name),lower(?1))>0)) AND (?2 IS NULL OR address>?2) ORDER BY address LIMIT ?3").map_err(err)?;
        let result = statement
            .query_map(params![query, after.map(key), count.min(512) as i64], |r| {
                Ok(FunctionFact {
                    address: address(r.get(0)?),
                    name: r.get(1)?,
                    size: r.get::<_, i64>(2)? as u64,
                    source: r.get(3)?,
                    confidence: r.get(4)?,
                })
            })
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err);
        result
    }
    pub fn aliases(&self, va: u64) -> Result<Vec<String>> {
        let mut s = self
            .db
            .prepare("SELECT DISTINCT name FROM aliases WHERE address=?1 ORDER BY name")
            .map_err(err)?;
        let result = s
            .query_map([key(va)], |r| r.get(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err);
        result
    }
    pub fn strings(
        &self,
        query: &str,
        after: Option<(u64, String)>,
        count: usize,
    ) -> Result<Vec<StringFact>> {
        let (va, enc) = after
            .map(|(a, e)| (Some(key(a)), e))
            .unwrap_or((None, String::new()));
        let mut s = self.db.prepare("SELECT address,end,encoding,text,truncated,source FROM strings WHERE (?1='' OR instr(lower(text),lower(?1))>0) AND (?2 IS NULL OR (address,encoding)>(?2,?3)) ORDER BY address,encoding LIMIT ?4").map_err(err)?;
        let result = s
            .query_map(params![query, va, enc, count.min(512) as i64], |r| {
                Ok(StringFact {
                    address: address(r.get(0)?),
                    end: address(r.get(1)?),
                    encoding: r.get(2)?,
                    text: r.get(3)?,
                    truncated: r.get(4)?,
                    source: r.get(5)?,
                })
            })
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err);
        result
    }
    pub fn xrefs(
        &self,
        va: u64,
        end: u64,
        incoming: bool,
        after: Option<(u64, u64, String)>,
        count: usize,
    ) -> Result<Vec<XrefFact>> {
        // incoming 对区间查询可覆盖字符串内部地址；outgoing 支持函数/指令范围。
        let column = if incoming { "dst" } else { "src" };
        let source = if incoming {
            "xrefs"
        } else {
            "(SELECT src,dst,kind,confidence,evidence FROM xrefs UNION ALL SELECT site,site,'unresolved-indirect',0,evidence FROM unresolved)"
        };
        let sql = format!("SELECT src,dst,kind,confidence,evidence FROM {source} WHERE {column}>=?1 AND {column}<?2 AND (?3 IS NULL OR (src,dst,kind)>(?3,?4,?5)) ORDER BY src,dst,kind LIMIT ?6");
        let (src, dst, kind) =
            after
                .map(|(s, d, k)| (Some(key(s)), key(d), k))
                .unwrap_or((None, 0, String::new()));
        let mut s = self.db.prepare(&sql).map_err(err)?;
        let result = s
            .query_map(
                params![key(va), key(end), src, dst, kind, count.min(512) as i64],
                |r| {
                    Ok(XrefFact {
                        from: address(r.get(0)?),
                        to: address(r.get(1)?),
                        kind: r.get(2)?,
                        confidence: r.get(3)?,
                        evidence: r.get(4)?,
                    })
                },
            )
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err);
        result
    }
    pub fn symbols(
        &self,
        kind: &str,
        query: &str,
        offset: usize,
        count: usize,
    ) -> Result<Vec<SymbolFact>> {
        let mut s = self.db.prepare("SELECT address,name,kind,source FROM symbols WHERE kind=?1 AND instr(lower(name),lower(?2))>0 ORDER BY name,address LIMIT ?3 OFFSET ?4").map_err(err)?;
        let result = s
            .query_map(
                params![kind, query, count.min(512) as i64, offset as i64],
                |r| {
                    Ok(SymbolFact {
                        address: address(r.get(0)?),
                        name: r.get(1)?,
                        kind: r.get(2)?,
                        source: r.get(3)?,
                    })
                },
            )
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err);
        result
    }
    pub fn preferred(&self) -> Option<u64> {
        self.db
            .query_row(
                "SELECT address FROM aliases WHERE name='JNI_OnLoad' LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .ok()
            .map(address)
            .or_else(|| {
                self.db
                    .query_row(
                        "SELECT address FROM functions ORDER BY confidence DESC,address LIMIT 1",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .ok()
                    .map(address)
            })
    }
    pub fn label(&self, va: u64) -> Option<String> {
        self.db.query_row("SELECT name FROM functions WHERE address=?1",[key(va)],|r|r.get(0)).ok()
            .or_else(||self.db.query_row("SELECT name FROM symbols WHERE address=?1 AND kind='import' LIMIT 1",[key(va)],|r|r.get(0)).ok())
            .or_else(||self.db.query_row("SELECT text FROM strings WHERE address<=?1 AND end>?1 ORDER BY address DESC LIMIT 1",[key(va)],|r|r.get::<_,String>(0)).ok().map(|s|format!("\"{}\"",s.chars().take(100).collect::<String>())))
    }
    pub fn owner(&self, va: u64) -> Option<String> {
        self.db.query_row("SELECT f.name,r.start FROM ranges r JOIN functions f ON f.address=r.entry WHERE r.start<=?1 AND r.end>?1 ORDER BY r.start DESC LIMIT 1",[key(va)],|r|Ok(format!("{} + {:#x} [range evidence]",r.get::<_,String>(0)?,va-address(r.get(1)?)))).ok()
    }
}
