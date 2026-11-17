//! `database_query`: a query against a database the machine runs itself
//! (PostgreSQL, MySQL or MariaDB from the distribution, as a systemd unit),
//! for the panel's Database tab. Containers go through `service_exec`.
//!
//! The panel only sends the query. The commands are fixed here, and the
//! query, database name and nonce reach them as settings, never as shell
//! text. PostgreSQL runs as the service's own user, so it signs in the way
//! the distribution sets it up (peer authentication); MySQL and MariaDB run
//! as root over the local socket, or with root's `~/.my.cnf`.
//!
//! The output is printed the way the panel's container commands print it:
//! sections marked with the nonce, and the client's output as unpadded
//! base64, so the log stays plain ASCII lines and the daemon's redaction has
//! nothing in it to change.

use std::fs;
use std::path::Path;
use std::time::Duration;

use daemon_backup::Strategy;
use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext};
use daemon_services::{ManagedService, RunBy};
use serde_json::{json, Value};

pub const MAX_SQL: usize = 20_000;

const MAX_DATABASE: usize = 128;

/// The client stops at 55s and the statement at 50s, before this.
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Mysql,
}

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Engine::Postgres => "postgres",
            Engine::Mysql => "mysql",
        }
    }
}

#[derive(Debug)]
pub struct Query<'a> {
    pub engine: &'a str,
    pub database: Option<&'a str>,
    pub sql: &'a str,
    pub read_only: bool,
    pub count: bool,
    pub nonce: &'a str,
}

/// Which client a service takes, and for PostgreSQL the user it runs as:
/// the same services the daemon backs up with pg_dumpall or mysqldump.
pub fn engine_of(service: &ManagedService) -> Option<(Engine, Option<String>)> {
    if !matches!(service.run_by, RunBy::Systemd { .. }) {
        return None;
    }

    match Strategy::for_service(service)? {
        Strategy::Postgres { user } => Some((Engine::Postgres, Some(user))),
        Strategy::Mysql => Some((Engine::Mysql, None)),
        _ => None,
    }
}

/// Everything the panel sent, checked before anything runs.
pub fn check(engine: Engine, query: &Query) -> Result<(), Failure> {
    let refuse = |why: &str| Failure::new("database", why.to_string());

    if query.engine != engine.name() {
        return Err(refuse(&format!(
            "this service is a {} database, not {}",
            engine.name(),
            query.engine
        )));
    }

    if query.nonce.len() != 32
        || !query
            .nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refuse("the nonce must be 32 lowercase hex characters"));
    }

    if query.sql.trim().is_empty() {
        return Err(refuse("there's no query to run"));
    }
    if query.sql.len() > MAX_SQL {
        return Err(refuse(&format!("the query is over {MAX_SQL} bytes")));
    }
    if query.sql.contains('\0') {
        return Err(refuse("the query has a NUL byte in it"));
    }
    // psql runs a -c string that starts with a backslash as its own command,
    // and \! runs a shell.
    if engine == Engine::Postgres && query.sql.trim_start().starts_with('\\') {
        return Err(refuse("backslash commands aren't run here, only SQL"));
    }

    if let Some(database) = query.database {
        let lower = database.to_ascii_lowercase();
        if database.len() > MAX_DATABASE
            || database.chars().any(char::is_control)
            // A connection string would send the client somewhere else.
            || database.contains('=')
            || lower.starts_with("postgres://")
            || lower.starts_with("postgresql://")
        {
            return Err(refuse("give the database's name only"));
        }
    }

    Ok(())
}

pub async fn query(
    ctx: &JobContext,
    service: &ManagedService,
    query: &Query<'_>,
) -> Result<Value, Failure> {
    let (engine, user) = engine_of(service).ok_or_else(|| {
        Failure::new(
            "database",
            format!(
                "{} isn't a PostgreSQL, MySQL or MariaDB database this machine runs itself",
                service.name
            ),
        )
    })?;
    check(engine, query)?;

    let (script, sql, run_as, home) = match engine {
        Engine::Postgres => {
            let user = user.unwrap_or_else(|| "postgres".into());
            let ids = daemon_files::lookup_user(&user).ok_or_else(|| {
                Failure::new(
                    "database",
                    format!("there's no {user} user on this machine"),
                )
            })?;
            (
                POSTGRES,
                query.sql.to_string(),
                Some(ids),
                home_of(&user).unwrap_or_else(|| "/tmp".into()),
            )
        }
        Engine::Mysql => (
            MYSQL,
            mysql_sql(query),
            None,
            home_of("root").unwrap_or_else(|| "/root".into()),
        ),
    };

    let flag = |on: bool| if on { "1" } else { "" };
    let env = [
        ("SOS_SQL", sql.as_str()),
        ("SOS_DB", query.database.unwrap_or("")),
        ("SOS_NONCE", query.nonce),
        ("SOS_RO", flag(query.read_only)),
        ("SOS_COUNT", flag(query.count)),
        ("HOME", home.as_str()),
    ];
    let script = format!("{script}\n{PRINT}");
    let mut cancel = ctx.cancel.clone();

    match run_child(
        "sh",
        &["-c", &script],
        Some(Path::new("/")),
        &env,
        TIMEOUT,
        &mut cancel,
        &ctx.progress,
        run_as,
    )
    .await
    {
        ChildOutcome::Exited { code, .. } => Ok(json!({ "exit_code": code })),
        ChildOutcome::TimedOut { .. } => Err(Failure::new(
            "database",
            format!("the query was still running after {}s", TIMEOUT.as_secs()),
        )),
        ChildOutcome::Cancelled { .. } => Err(Failure::new("cancelled", "query cancelled")),
        ChildOutcome::Unstartable(e) => Err(Failure::new("database", e)),
    }
}

/// The query as the mysql client gets it: read-only first when asked, and
/// the changed-rows line after it, marked with the nonce (checked as hex).
fn mysql_sql(query: &Query) -> String {
    let mut sql = String::new();
    if query.read_only {
        sql.push_str("SET SESSION TRANSACTION READ ONLY; ");
    }
    sql.push_str(query.sql);
    if query.count {
        let nonce = query.nonce;
        sql.push_str(&format!(
            "\n;SELECT CONCAT('{nonce} ', ROW_COUNT()) AS `{nonce}`"
        ));
    }
    sql
}

fn home_of(user: &str) -> Option<String> {
    let text = fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|line| {
        let parts: Vec<&str> = line.split(':').collect();
        (parts.first() == Some(&user) && parts.len() > 5 && !parts[5].is_empty())
            .then(|| parts[5].to_string())
    })
}

const POSTGRES: &str = r#"O=$(mktemp) E=$(mktemp)
trap 'rm -f "$O" "$E"' EXIT
T=; command -v timeout >/dev/null 2>&1 && T="timeout 55"
D="${SOS_DB:-postgres}"
export PGCLIENTENCODING=UTF8 PGOPTIONS="-c statement_timeout=50s${SOS_RO:+ -c default_transaction_read_only=on}"
if [ -n "$SOS_COUNT" ]; then
    $T psql -X -q -v ON_ERROR_STOP=1 --csv -P null=NULL -d "$D" -c "$SOS_SQL" -c "\\echo $SOS_NONCE :ROW_COUNT" > "$O" 2> "$E"
else
    $T psql -X -q -v ON_ERROR_STOP=1 --csv -P null=NULL -d "$D" -c "$SOS_SQL" > "$O" 2> "$E"
fi
code=$?"#;

// --binary-mode turns off the client's own commands (system, \!), which
// would otherwise run a shell as root. A client without it isn't used.
const MYSQL: &str = r#"O=$(mktemp) E=$(mktemp)
trap 'rm -f "$O" "$E"' EXIT
T=; command -v timeout >/dev/null 2>&1 && T="timeout 55"
C=mysql; command -v mariadb >/dev/null 2>&1 && C=mariadb
D="$SOS_DB"
if ! $C --help 2>/dev/null | grep -q -- '--binary-mode'; then
    echo "This $C client is too old to run queries from the panel safely. Update it, then try again." > "$E"
    code=2
else
    L="SET SESSION max_execution_time=50000;"
    $C --version 2>/dev/null | grep -qi mariadb && L="SET SESSION max_statement_time=50;"
    $T $C --batch --unbuffered --binary-mode --default-character-set=utf8mb4 ${D:+-D "$D"} -e "SELECT CONNECTION_ID() AS id;$L$SOS_SQL" > "$O" 2> "$E"
    code=$?
    I=$(sed -n 2p "$O"); sed -i 1,2d "$O"
    case "$I" in *[!0-9]*|'') ;; *) [ "$code" = 124 ] && $C -e "KILL $I" >/dev/null 2>&1 ;; esac
fi"#;

const PRINT: &str = r#"echo "$SOS_NONCE database $D"
echo "$SOS_NONCE result"
head -c 160000 "$O" | head -n 400 | base64 | tr -d '=\n' | fold -w 3000
echo
echo "$SOS_NONCE error"
head -c 4000 "$E" | base64 | tr -d '=\n' | fold -w 3000
echo
echo "$SOS_NONCE end $code $(wc -c < "$O") $(wc -l < "$O")""#;

#[cfg(test)]
mod tests {
    use super::*;

    fn query<'a>(sql: &'a str) -> Query<'a> {
        Query {
            engine: "postgres",
            database: None,
            sql,
            read_only: true,
            count: false,
            nonce: "0123456789abcdef0123456789abcdef",
        }
    }

    #[test]
    fn a_plain_query_passes() {
        assert!(check(Engine::Postgres, &query("SELECT 1")).is_ok());
        let named = Query {
            database: Some("shop"),
            ..query("SELECT 1")
        };
        assert!(check(Engine::Postgres, &named).is_ok());
    }

    #[test]
    fn backslash_commands_are_refused_for_psql() {
        assert!(check(Engine::Postgres, &query("\\! id")).is_err());
        assert!(check(Engine::Postgres, &query("  \\! id")).is_err());
        assert!(check(Engine::Postgres, &query("SELECT '\\'")).is_ok());
    }

    #[test]
    fn the_engine_must_match_the_service() {
        assert!(check(Engine::Mysql, &query("SELECT 1")).is_err());
        let mysql = Query {
            engine: "mysql",
            ..query("SELECT 1")
        };
        assert!(check(Engine::Mysql, &mysql).is_ok());
    }

    #[test]
    fn the_nonce_is_hex_only() {
        for nonce in [
            "",
            "0123",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde'",
        ] {
            let q = Query {
                nonce,
                ..query("SELECT 1")
            };
            assert!(check(Engine::Postgres, &q).is_err(), "{nonce}");
        }
    }

    #[test]
    fn connection_strings_are_refused_as_database_names() {
        for database in [
            "host=elsewhere user=x",
            "postgres://elsewhere/db",
            "PostgreSQL://elsewhere/db",
            "shop\nother",
        ] {
            let q = Query {
                database: Some(database),
                ..query("SELECT 1")
            };
            assert!(check(Engine::Postgres, &q).is_err(), "{database}");
        }
    }

    #[test]
    fn empty_long_and_nul_queries_are_refused() {
        assert!(check(Engine::Postgres, &query("   ")).is_err());
        assert!(check(Engine::Postgres, &query("SELECT 1\0")).is_err());
        let long = "x".repeat(MAX_SQL + 1);
        assert!(check(Engine::Postgres, &query(&long)).is_err());
    }

    #[test]
    fn mysql_gets_read_only_and_the_changed_rows_line() {
        let q = Query {
            engine: "mysql",
            count: true,
            ..query("UPDATE t SET a = 1")
        };
        assert_eq!(
            mysql_sql(&q),
            "SET SESSION TRANSACTION READ ONLY; UPDATE t SET a = 1\n;SELECT CONCAT('0123456789abcdef0123456789abcdef ', ROW_COUNT()) AS `0123456789abcdef0123456789abcdef`"
        );
        let write = Query {
            read_only: false,
            count: false,
            ..q
        };
        assert_eq!(mysql_sql(&write), "UPDATE t SET a = 1");
    }
}
