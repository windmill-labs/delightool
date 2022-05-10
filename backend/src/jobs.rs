/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use chrono::Duration;
use sql_builder::prelude::*;
use sqlx::{Postgres, Transaction};
use std::collections::HashMap;

use crate::{
    audit::{audit_log, ActionKind},
    db::{UserDB, DB},
    error,
    error::Error,
    scripts::ScriptHash,
    users::{owner_to_token_owner, Authed},
    utils::{require_admin, Pagination, StripPath},
};
use axum::{
    extract::{Extension, Path, Query},
    routing::{get, post},
    Json, Router,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sql_builder::SqlBuilder;

use ulid::Ulid;
use uuid::Uuid;

const MAX_NB_OF_JOBS_IN_Q_PER_USER: i64 = 10;
const MAX_DURATION_LAST_1200: i64 = 400;

pub fn make_service() -> Router {
    Router::new()
        .route("/run/p/*script_path", post(run_job_by_path))
        .route("/run/h/:hash", post(run_job_by_hash))
        .route("/run/preview", post(run_preview_job))
        .route("/list", get(list_jobs))
        .route("/queue/list", get(list_queue_jobs))
        .route("/queue/cancel/:id", post(cancel_job))
        .route("/completed/list", get(list_completed_jobs))
        .route("/completed/get/:id", get(get_completed_job))
        .route("/completed/delete/:id", post(delete_completed_job))
        .route("/get/:id", get(get_job))
        .route("/getupdate/:id", get(get_job_update))
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct QueuedJob {
    pub id: Uuid,
    pub parent_job: Option<Uuid>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub scheduled_for: chrono::DateTime<chrono::Utc>,
    pub running: bool,
    pub script_hash: Option<ScriptHash>,
    pub script_path: Option<String>,
    pub args: Option<serde_json::Value>,
    pub logs: Option<String>,
    pub raw_code: Option<String>,
    pub canceled: bool,
    pub canceled_by: Option<String>,
    pub canceled_reason: Option<String>,
    pub scheduled: bool,
    pub last_ping: Option<chrono::DateTime<chrono::Utc>>,
    pub job_kind: JobKind,
    pub env_id: Option<i32>,
    pub schedule_path: Option<String>,
    pub permissioned_as: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct CompletedJob {
    id: Uuid,
    parent_job: Option<Uuid>,
    created_by: String,
    created_at: chrono::DateTime<chrono::Utc>,
    duration: i32,
    success: bool,
    script_hash: Option<ScriptHash>,
    script_path: Option<String>,
    args: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    logs: Option<String>,
    deleted: bool,
    raw_code: Option<String>,
    canceled: bool,
    canceled_by: Option<String>,
    canceled_reason: Option<String>,
    scheduled: bool,
    job_kind: JobKind,
    env_id: i32,
    schedule_path: Option<String>,
    permissioned_as: String,
}

#[derive(Deserialize, Clone, Copy)]
struct RunJobQuery {
    scheduled_for: Option<chrono::DateTime<chrono::Utc>>,
    scheduled_in_secs: Option<i64>,
    parent_job: Option<Uuid>,
}

impl RunJobQuery {
    fn get_scheduled_for(self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.scheduled_for.or_else(|| {
            self.scheduled_in_secs
                .map(|s| chrono::Utc::now() + Duration::seconds(s))
        })
    }
}

async fn run_job_by_path(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(script_path): Path<StripPath>,
    axum::Json(args): axum::Json<Option<Map<String, Value>>>,
    Query(run_query): Query<RunJobQuery>,
) -> error::Result<(StatusCode, String)> {
    let script_path = script_path.to_path();
    let mut tx = user_db.begin(&authed).await?;
    let script_hash = get_latest_hash_for_path(&mut tx, script_path).await?;
    let (uuid, tx) = push(
        tx,
        &JobPayload::ScriptHash {
            hash: script_hash,
            path: script_path.to_owned(),
        },
        args,
        &authed.username,
        owner_to_token_owner(&authed.username, false),
        run_query.get_scheduled_for(),
        None,
        run_query.parent_job,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, uuid.to_string()))
}

pub async fn get_latest_hash_for_path<'c>(
    db: &mut Transaction<'c, Postgres>,
    script_path: &str,
) -> error::Result<ScriptHash> {
    let script_hash_o = sqlx::query_scalar!(
        "select hash from script where path = $1 AND 
    created_at = (SELECT max(created_at) FROM script WHERE path = $1) AND
    deleted = false",
        script_path
    )
    .fetch_optional(db)
    .await?;

    let script_hash = crate::utils::not_found_if_none(script_hash_o, "ScriptHash", script_path)?;

    Ok(ScriptHash(script_hash))
}

async fn run_job_by_hash(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(script_hash): Path<ScriptHash>,
    axum::Json(args): axum::Json<Option<Map<String, Value>>>,
    Query(run_query): Query<RunJobQuery>,
) -> error::Result<(StatusCode, String)> {
    let hash = script_hash.0;
    let mut tx = user_db.begin(&authed).await?;
    let path = get_path_for_hash(&mut tx, hash).await?;
    let (uuid, tx) = push(
        tx,
        &JobPayload::ScriptHash {
            hash: ScriptHash(hash),
            path,
        },
        args,
        &authed.username,
        owner_to_token_owner(&authed.username, false),
        run_query.get_scheduled_for(),
        None,
        run_query.parent_job,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, uuid.to_string()))
}

pub async fn get_path_for_hash<'c>(
    db: &mut Transaction<'c, Postgres>,
    hash: i64,
) -> error::Result<String> {
    let path = sqlx::query_scalar!("select path from script where hash = $1", hash)
        .fetch_one(db)
        .await?;
    Ok(path)
}

async fn run_preview_job(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Json(preview): Json<Preview>,
    Query(sch_query): Query<RunJobQuery>,
) -> error::Result<(StatusCode, String)> {
    let tx = user_db.begin(&authed).await?;
    let (uuid, tx) = push(
        tx,
        &JobPayload::Code(RawCode {
            content: preview.content,
            path: preview.path,
        }),
        preview.args,
        &authed.username,
        owner_to_token_owner(&authed.username, false),
        sch_query.get_scheduled_for(),
        None,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, uuid.to_string()))
}
#[derive(Deserialize)]
pub struct ListQueueQuery {
    pub script_path_start: Option<String>,
    pub script_path_exact: Option<String>,
    pub script_hash: Option<String>,
    pub created_by: Option<String>,
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    pub running: Option<bool>,
    pub parent_job: Option<String>,
    pub order_desc: Option<bool>,
    pub job_kinds: Option<String>,
}

fn list_queue_jobs_query(lq: &ListQueueQuery, fields: &[&str]) -> SqlBuilder {
    let mut sqlb = SqlBuilder::select_from("queue")
        .fields(fields)
        .order_by("created_at", lq.order_desc.unwrap_or(true))
        .limit(1000)
        .clone();

    if let Some(ps) = &lq.script_path_start {
        sqlb.and_where_like_left("script_path", "?".bind(ps));
    }
    if let Some(p) = &lq.script_path_exact {
        sqlb.and_where_eq("script_path", "?".bind(p));
    }
    if let Some(h) = &lq.script_hash {
        sqlb.and_where_eq("script_hash", "?".bind(h));
    }
    if let Some(cb) = &lq.created_by {
        sqlb.and_where_eq("created_by", "?".bind(cb));
    }
    if let Some(r) = &lq.running {
        sqlb.and_where_eq("running", &r);
    }
    if let Some(pj) = &lq.parent_job {
        sqlb.and_where_eq("parent_job", "?".bind(pj));
    }
    if let Some(dt) = &lq.created_before {
        sqlb.and_where_lt("created_at", format!("to_timestamp({})", dt.timestamp()));
    }
    if let Some(dt) = &lq.created_after {
        sqlb.and_where_gt("created_at", format!("to_timestamp({})", dt.timestamp()));
    }
    if let Some(jk) = &lq.job_kinds {
        sqlb.and_where_in(
            "job_kind",
            &jk.split(',').into_iter().map(quote).collect::<Vec<_>>(),
        );
    }

    sqlb
}

async fn list_queue_jobs(
    Extension(db): Extension<DB>,
    Query(lq): Query<ListQueueQuery>,
) -> error::JsonResult<Vec<QueuedJob>> {
    let sql = list_queue_jobs_query(&lq, &["*"]).sql()?;
    let jobs = sqlx::query_as::<_, QueuedJob>(&sql).fetch_all(&db).await?;
    Ok(Json(jobs))
}

async fn list_jobs(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Query(pagination): Query<Pagination>,
    Query(lq): Query<ListCompletedQuery>,
) -> error::JsonResult<Vec<Job>> {
    let (per_page, offset) = crate::utils::paginate(pagination);
    let lqc = lq.clone();
    let sqlq = list_queue_jobs_query(
        &ListQueueQuery {
            script_path_start: lq.script_path_start,
            script_path_exact: lq.script_path_exact,
            script_hash: lq.script_hash,
            created_by: lq.created_by,
            created_before: lq.created_before,
            created_after: lq.created_after,
            running: None,
            parent_job: lq.parent_job,
            order_desc: Some(true),
            job_kinds: lq.job_kinds,
        },
        &[
            "'QueuedJob' as typ",
            "id",
            "parent_job",
            "created_by",
            "created_at",
            "started_at",
            "scheduled_for",
            "running",
            "script_hash",
            "script_path",
            "args",
            "null as duration",
            "null as success",
            "false as deleted",
            "canceled",
            "canceled_by",
            "scheduled",
            "job_kind",
            "env_id",
            "schedule_path",
            "permissioned_as",
        ],
    );
    let sqlc = list_completed_jobs_query(
        per_page + offset,
        0,
        &ListCompletedQuery {
            order_desc: Some(true),
            ..lqc
        },
        &[
            "'CompletedJob' as typ",
            "id",
            "parent_job",
            "created_by",
            "created_at",
            "null as started_at",
            "null as scheduled_for",
            "null as running",
            "script_hash",
            "script_path",
            "args",
            "duration",
            "success",
            "deleted",
            "canceled",
            "canceled_by",
            "scheduled",
            "job_kind",
            "env_id",
            "schedule_path",
            "permissioned_as",
        ],
    );
    let sql = format!(
        "{} UNION ALL {} ORDER BY created_at DESC LIMIT {} OFFSET {};",
        &sqlq.subquery()?,
        &sqlc.subquery()?,
        per_page,
        offset
    );
    let mut tx = user_db.begin(&authed).await?;
    let jobs: Vec<UnifiedJob> = sqlx::query_as(&sql).fetch_all(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(jobs.into_iter().map(From::from).collect()))
}
#[derive(Deserialize, Clone)]
pub struct ListCompletedQuery {
    pub script_path_start: Option<String>,
    pub script_path_exact: Option<String>,
    pub script_hash: Option<String>,
    pub created_by: Option<String>,
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    pub success: Option<bool>,
    pub parent_job: Option<String>,
    pub order_desc: Option<bool>,
    pub job_kinds: Option<String>,
}
fn list_completed_jobs_query(
    per_page: usize,
    offset: usize,
    lq: &ListCompletedQuery,
    fields: &[&str],
) -> SqlBuilder {
    let mut sqlb = SqlBuilder::select_from("completed_job")
        .fields(fields)
        .order_by("created_at", lq.order_desc.unwrap_or(true))
        .offset(offset)
        .limit(per_page)
        .clone();

    if let Some(ps) = &lq.script_path_start {
        sqlb.and_where_like_left("script_path", "?".bind(ps));
    }
    if let Some(p) = &lq.script_path_exact {
        sqlb.and_where_eq("script_path", "?".bind(p));
    }
    if let Some(h) = &lq.script_hash {
        sqlb.and_where_eq("script_hash", "?".bind(h));
    }
    if let Some(cb) = &lq.created_by {
        sqlb.and_where_eq("created_by", "?".bind(cb));
    }
    if let Some(r) = &lq.success {
        sqlb.and_where_eq("success", r);
    }
    if let Some(pj) = &lq.parent_job {
        sqlb.and_where_eq("parent_job", "?".bind(pj));
    }
    if let Some(dt) = &lq.created_before {
        sqlb.and_where_lt("created_at", format!("to_timestamp({})", dt.timestamp()));
    }
    if let Some(dt) = &lq.created_after {
        sqlb.and_where_gt("created_at", format!("to_timestamp({})", dt.timestamp()));
    }
    if let Some(jk) = &lq.job_kinds {
        sqlb.and_where_in(
            "job_kind",
            &jk.split(',').into_iter().map(quote).collect::<Vec<_>>(),
        );
    }

    sqlb
}

async fn list_completed_jobs(
    Extension(db): Extension<DB>,
    Query(pagination): Query<Pagination>,
    Query(lq): Query<ListCompletedQuery>,
) -> error::JsonResult<Vec<CompletedJob>> {
    let (per_page, offset) = crate::utils::paginate(pagination);

    let sql = list_completed_jobs_query(
        per_page,
        offset,
        &lq,
        &[
            "id",
            "parent_job",
            "created_by",
            "created_at",
            "duration",
            "success",
            "script_hash",
            "script_path",
            "args",
            "result",
            "null as logs",
            "deleted",
            "canceled",
            "canceled_by",
            "canceled_reason",
            "scheduled",
            "job_kind",
            "env_id",
            "schedule_path",
            "permissioned_as",
            "null as raw_code",
        ],
    )
    .sql()?;
    let jobs = sqlx::query_as::<_, CompletedJob>(&sql)
        .fetch_all(&db)
        .await?;
    Ok(Json(jobs))
}

async fn get_completed_job(
    Extension(db): Extension<DB>,
    Path(id): Path<Uuid>,
) -> error::JsonResult<CompletedJob> {
    let job_o = sqlx::query_as::<_, CompletedJob>("SELECT * FROM completed_job WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await?;

    let job = crate::utils::not_found_if_none(job_o, "Completed Job", id.to_string())?;
    Ok(Json(job))
}

async fn cancel_job(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(id): Path<Uuid>,
    Json(CancelJob { reason }): Json<CancelJob>,
) -> error::Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    let job_option = sqlx::query_scalar!(
        "UPDATE queue SET canceled = true, canceled_by = $1, canceled_reason = $2 \
         WHERE id = $3 AND schedule_path IS NULL \
         RETURNING id",
        &authed.username,
        reason,
        id
    )
    .fetch_optional(&mut tx)
    .await?;

    if let Some(id) = job_option {
        audit_log(
            &mut tx,
            &authed.username,
            "jobs.delete",
            ActionKind::Delete,
            Some(&id.to_string()),
            None,
        )
        .await?;
        Ok(id.to_string())
    } else {
        let (job_o, tx) = get_job_from_id(tx, id).await?;
        tx.commit().await?;
        let err = match job_o {
            Some(Job::CompletedJob(_)) => error::Error::BadRequest(format!(
                "queued job id {} exists but is already completed and cannot be canceled",
                id
            )),
            Some(Job::QueuedJob(job)) if job.schedule_path.is_some() => {
                error::Error::BadRequest(format!(
                    "queued job id {} exists but has been created by a scheduler 
                and can only be only canceled by disabling the parent scheduler",
                    id
                ))
            }
            _ => error::Error::NotFound(format!("queued job id {} does not exist", id)),
        };
        Err(err)
    }
}

async fn delete_completed_job(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(id): Path<Uuid>,
) -> error::JsonResult<CompletedJob> {
    let mut tx = user_db.begin(&authed).await?;

    require_admin(&mut tx, &authed.username).await?;
    let job_o = sqlx::query_as::<_, CompletedJob>(
        "UPDATE completed_job SET logs = '', deleted = true WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .fetch_optional(&mut tx)
    .await?;

    let job = crate::utils::not_found_if_none(job_o, "Completed Job", id.to_string())?;

    audit_log(
        &mut tx,
        &authed.username,
        "jobs.delete",
        ActionKind::Delete,
        Some(&id.to_string()),
        None,
    )
    .await?;

    tx.commit().await?;
    Ok(Json(job))
}

#[derive(Deserialize)]
pub struct JobUpdateQuery {
    pub running: bool,
    pub log_offset: usize,
}

#[derive(Serialize)]
pub struct JobUpdate {
    pub running: Option<bool>,
    pub completed: Option<bool>,
    pub new_logs: Option<String>,
}

async fn get_job_update(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(id): Path<Uuid>,
    Query(JobUpdateQuery {
        running,
        log_offset,
    }): Query<JobUpdateQuery>,
) -> error::JsonResult<JobUpdate> {
    let tx = user_db.begin(&authed).await?;

    let (job_o, tx) = get_job_from_id(tx, id).await?;
    let job = crate::utils::not_found_if_none(job_o, "Completed Job", id.to_string())?;
    let (running, completed) = match &job {
        Job::QueuedJob(qj) => {
            let nrunning = if qj.running != running {
                Some(qj.running)
            } else {
                None
            };
            (nrunning, None)
        }
        Job::CompletedJob(_) => (Some(false), Some(true)),
    };
    let new_logs_all = match job {
        Job::QueuedJob(qj) => qj.logs,
        Job::CompletedJob(cj) => cj.logs,
    };

    tx.commit().await?;
    Ok(Json(JobUpdate {
        running,
        completed,
        new_logs: new_logs_all.and_then(|logs| {
            let len = logs.len();
            if log_offset >= len {
                None
            } else {
                Some(logs[log_offset..].to_string())
            }
        }),
    }))
}

async fn get_job(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(id): Path<Uuid>,
) -> error::JsonResult<Job> {
    let tx = user_db.begin(&authed).await?;
    let (job_o, tx) = get_job_from_id(tx, id).await?;
    let job = crate::utils::not_found_if_none(job_o, "Completed Job", id.to_string())?;
    tx.commit().await?;
    Ok(Json(job))
}

async fn get_job_from_id<'c>(
    mut tx: Transaction<'c, Postgres>,
    id: Uuid,
) -> error::Result<(Option<Job>, Transaction<'c, Postgres>)> {
    let cjob_option =
        sqlx::query_as::<_, CompletedJob>("SELECT * FROM completed_job WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut tx)
            .await?;
    let job_option = match cjob_option {
        Some(job) => Some(Job::CompletedJob(job)),
        None => sqlx::query_as::<_, QueuedJob>(
            "SELECT *
            FROM queue WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut tx)
        .await?
        .map(Job::QueuedJob),
    };
    Ok((job_option, tx))
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum Job {
    QueuedJob(QueuedJob),
    CompletedJob(CompletedJob),
}

#[derive(sqlx::Type, Serialize, Deserialize, Debug)]
#[sqlx(type_name = "JOB_KIND", rename_all = "lowercase")]
#[serde(rename_all(serialize = "lowercase"))]
pub enum JobKind {
    Script,
    Preview,
    Dependencies,
}

#[derive(sqlx::FromRow)]
struct UnifiedJob {
    typ: String,
    id: Uuid,
    parent_job: Option<Uuid>,
    created_by: String,
    created_at: chrono::DateTime<chrono::Utc>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    scheduled_for: Option<chrono::DateTime<chrono::Utc>>,
    running: Option<bool>,
    script_hash: Option<ScriptHash>,
    script_path: Option<String>,
    args: Option<serde_json::Value>,
    duration: Option<i32>,
    success: Option<bool>,
    deleted: bool,
    canceled: bool,
    canceled_by: Option<String>,
    scheduled: bool,
    job_kind: JobKind,
    env_id: Option<i32>,
    schedule_path: Option<String>,
    permissioned_as: String,
}

impl From<UnifiedJob> for Job {
    fn from(uj: UnifiedJob) -> Self {
        match uj.typ.as_ref() {
            "CompletedJob" => Job::CompletedJob(CompletedJob {
                id: uj.id,
                parent_job: uj.parent_job,
                created_by: uj.created_by,
                created_at: uj.created_at,
                duration: uj.duration.unwrap(),
                success: uj.success.unwrap(),
                script_hash: uj.script_hash,
                script_path: uj.script_path,
                args: uj.args,
                result: None,
                logs: None,
                deleted: uj.deleted,
                canceled: uj.canceled,
                canceled_by: uj.canceled_by,
                scheduled: uj.scheduled,
                raw_code: None,
                canceled_reason: None,
                job_kind: uj.job_kind,
                env_id: uj.env_id.unwrap(),
                schedule_path: uj.schedule_path,
                permissioned_as: uj.permissioned_as,
            }),
            "QueuedJob" => Job::QueuedJob(QueuedJob {
                id: uj.id,
                parent_job: uj.parent_job,
                created_by: uj.created_by,
                created_at: uj.created_at,
                started_at: uj.started_at,
                script_hash: uj.script_hash,
                script_path: uj.script_path,
                args: uj.args,
                running: uj.running.unwrap(),
                scheduled_for: uj.scheduled_for.unwrap(),
                logs: None,
                raw_code: None,
                canceled: uj.canceled,
                canceled_by: uj.canceled_by,
                canceled_reason: None,
                scheduled: uj.scheduled,
                last_ping: None,
                job_kind: uj.job_kind,
                env_id: uj.env_id,
                schedule_path: uj.schedule_path,
                permissioned_as: uj.permissioned_as,
            }),
            t => panic!("job type {} not valid", t),
        }
    }
}
#[derive(Deserialize)]
struct CancelJob {
    reason: Option<String>,
}

pub struct RawCode {
    content: String,
    path: Option<String>,
}

#[derive(Deserialize)]
struct Preview {
    content: String,
    path: Option<String>,
    args: Option<Map<String, Value>>,
}

pub enum JobPayload {
    ScriptHash { hash: ScriptHash, path: String },
    Code(RawCode),
    Dependencies(i32),
}

pub async fn push<'c>(
    mut tx: Transaction<'c, Postgres>,
    job_payload: &JobPayload,
    args: Option<Map<String, Value>>,
    user: &str,
    permissioned_as: String,
    scheduled_for_o: Option<chrono::DateTime<chrono::Utc>>,
    schedule_path: Option<String>,
    parent_job: Option<Uuid>,
) -> Result<(Uuid, Transaction<'c, Postgres>), Error> {
    let scheduled_for = scheduled_for_o.unwrap_or_else(chrono::Utc::now);
    let args_json = args.map(serde_json::Value::Object);
    let job_id: Uuid = Ulid::new().into();

    let rate_limiting_queue =
        sqlx::query_scalar!("SELECT COUNT(id) FROM queue WHERE created_by = $1", user)
            .fetch_one(&mut tx)
            .await?;

    if let Some(nb_jobs) = rate_limiting_queue {
        if nb_jobs > MAX_NB_OF_JOBS_IN_Q_PER_USER {
            return Err(error::Error::ExecutionErr(format!(
                "You have exceeded the number of authorized elements of queue at any given time: {}", MAX_NB_OF_JOBS_IN_Q_PER_USER)));
        }
    }

    let rate_limiting_duration = sqlx::query_scalar!(
        "SELECT SUM(duration) FROM completed_job WHERE created_by = $1 AND created_at > NOW() - INTERVAL '1200 seconds';",
        user
    )
    .fetch_one(&mut tx)
    .await?;

    if let Some(sum_duration) = rate_limiting_duration {
        if sum_duration > MAX_DURATION_LAST_1200 {
            return Err(error::Error::ExecutionErr(format!(
                "You have exceeded the scripts cumulative duration limit over the last 20m which is: {}", MAX_DURATION_LAST_1200)));
        }
    }

    let (script_hash, script_path, raw_code, job_kind, env_id) = match job_payload {
        JobPayload::ScriptHash { hash, path } => (
            Some(hash.0),
            Some(path.as_str()),
            None,
            JobKind::Script,
            None,
        ),
        JobPayload::Code(RawCode { content, path }) => (
            None,
            path.as_ref().map(|x| x.as_str()),
            Some(content),
            JobKind::Preview,
            None,
        ),
        &JobPayload::Dependencies(env_id) => {
            (None, None, None, JobKind::Dependencies, Some(env_id))
        }
    };
    let uuid = sqlx::query_scalar!(
        "INSERT INTO queue
            (id, parent_job, created_by, permissioned_as, scheduled_for, 
                script_hash, script_path, raw_code, args, scheduled, job_kind, env_id, schedule_path)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
        job_id,
        parent_job,
        user,
        permissioned_as,
        scheduled_for,
        script_hash,
        script_path.clone(),
        raw_code,
        args_json,
        scheduled_for_o.is_some(),
        job_kind: JobKind,
        env_id,
        schedule_path,
    )
    .fetch_one(&mut tx)
    .await?;
    let uuid_string = job_id.to_string();
    let uuid_str = uuid_string.as_str();
    let mut hm = HashMap::from([("uuid", uuid_str), ("permissioned_as", &permissioned_as)]);

    match job_kind {
        JobKind::Dependencies => {
            audit_log(
                &mut tx,
                &user,
                "jobs.run.dependencies",
                ActionKind::Execute,
                Some(&format!("{:?}", env_id)),
                Some(hm),
            )
            .await?
        }
        JobKind::Preview => {
            audit_log(
                &mut tx,
                &user,
                "jobs.run.preview",
                ActionKind::Execute,
                Some(&format!("preview {:?}", script_path)),
                Some(hm),
            )
            .await?
        }
        JobKind::Script => {
            let script_hash_str = ScriptHash(script_hash.unwrap()).to_string();
            hm.insert("hash", script_hash_str.as_str());
            audit_log(
                &mut tx,
                &user,
                "jobs.run.script",
                ActionKind::Execute,
                script_path,
                Some(hm),
            )
            .await?
        }
    }

    Ok((uuid, tx))
}

pub async fn add_completed_job(
    db: &DB,
    queued_job: QueuedJob,
    duration: i32,
    success: bool,
    result: Option<Map<String, Value>>,
    logs: String,
) -> Result<Uuid, Error> {
    let result_json = result.map(serde_json::Value::Object);
    let _ = sqlx::query!(
        "INSERT INTO completed_job
            (id, parent_job, created_by, created_at, duration, success, script_hash, script_path, \
         args, result, logs, 
            raw_code, canceled, canceled_by, canceled_reason, scheduled, job_kind, env_id, schedule_path, permissioned_as)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) \
         RETURNING id",
        queued_job.id,
        queued_job.parent_job,
        queued_job.created_by,
        queued_job.created_at,
        duration,
        success,
        queued_job.script_hash.map(|x| x.0),
        queued_job.script_path,
        queued_job.args,
        result_json,
        logs,
        queued_job.raw_code,
        queued_job.canceled,
        queued_job.canceled_by,
        queued_job.canceled_reason,
        queued_job.scheduled,
        queued_job.job_kind: JobKind,
        queued_job.env_id.unwrap_or(-1),
        queued_job.schedule_path,
        queued_job.permissioned_as
    )
    .fetch_one(db)
    .await?;
    Ok(queued_job.id)
}

pub async fn pull(
    db: &DB,
    number_of_jobs: u32,
    id: Option<String>,
    env_id_o: Option<i32>,
) -> Result<Vec<QueuedJob>, crate::Error> {
    let now = chrono::Utc::now();
    let id_filter = id
        .map(|x| format!(" AND id = '{}'", x))
        .unwrap_or_else(|| "".to_string());
    let query = format!(
        "UPDATE queue
            SET running = true, started_at = $1
            WHERE id IN (
                SELECT id
                FROM queue
                WHERE running = false AND scheduled_for <= $2 {}
                ORDER BY scheduled_for
                FOR UPDATE SKIP LOCKED
                LIMIT $3
            )
            RETURNING *",
        id_filter
    );

    let mut jobs: Vec<QueuedJob> = sqlx::query_as::<_, QueuedJob>(&query)
        .bind(now)
        .bind(now)
        .bind(number_of_jobs)
        .fetch_all(db)
        .await?;

    if let Some(env_id) = env_id_o {
        let ids = &jobs.iter().map(|x| x.id).collect::<Vec<_>>();
        sqlx::query!(
            "UPDATE queue SET env_id = $1 WHERE id = ANY($2) AND job_kind <> 'dependencies'",
            env_id,
            ids
        )
        .execute(db)
        .await?;
        jobs = jobs
            .into_iter()
            .map(|mut x| {
                if !matches!(x.job_kind, JobKind::Dependencies) {
                    x.env_id = Some(env_id);
                }
                x
            })
            .collect()
    }
    Ok(jobs)
}

pub async fn delete_job(db: &DB, job_id: Uuid) -> Result<(), crate::Error> {
    sqlx::query!("DELETE FROM queue WHERE id = $1", job_id)
        .execute(db)
        .await?;
    Ok(())
}
