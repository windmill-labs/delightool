/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use std::str::FromStr;

use crate::{
    audit::{audit_log, ActionKind},
    db::UserDB,
    error::{self, JsonResult, Result},
    jobs::{self, push, JobPayload},
    scripts::ScriptHash,
    users::Authed,
    utils::{get_owner_from_path, Pagination, StripPath},
};
use axum::{
    extract::{Extension, Path, Query},
    routing::{get, post},
    Json, Router,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::{FromRow, Postgres, Transaction};

pub fn make_service() -> Router {
    Router::new()
        .route("/list", get(list_schedule))
        .route("/get/*path", get(get_schedule))
        .route("/create", post(create_schedule))
        .route("/update/*path", post(edit_schedule))
        .route("/setenabled/*path", post(set_enabled))
        .route("/preview", post(preview_schedule))
}

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct Schedule {
    pub path: String,
    pub edited_by: String,
    pub edited_at: DateTime<chrono::Utc>,
    pub schedule: String,
    pub enabled: bool,
    pub script_path: Option<String>,
    pub script_hash: Option<i64>,
    pub args: Option<serde_json::Value>,
    pub extra_perms: serde_json::Value,
}

#[derive(Deserialize)]
pub struct NewSchedule {
    pub path: String,
    pub schedule: String,
    pub script_path: Option<String>,
    pub script_hash: Option<i64>,
    pub args: Option<serde_json::Value>,
}

pub async fn push_scheduled_job<'c>(
    tx: Transaction<'c, Postgres>,
    schedule: Schedule,
    script_hash_payload: (ScriptHash, String),
) -> Result<Transaction<'c, Postgres>> {
    let sched = cron::Schedule::from_str(&schedule.schedule)
        .map_err(|e| error::Error::BadRequest(e.to_string()))?;

    let next = sched
        .after(&(chrono::Utc::now() + Duration::seconds(1)))
        .next()
        .expect("a schedule should have a next event");

    let mut args: Option<Map<String, Value>> = None;

    if let Some(args_v) = schedule.args {
        if let Value::Object(args_m) = args_v {
            args = Some(args_m)
        } else {
            return Err(error::Error::ExecutionErr(
                "args of scripts needs to be dict".to_string(),
            ));
        }
    }

    let (_, tx) = push(
        tx,
        &JobPayload::ScriptHash {
            hash: script_hash_payload.0,
            path: script_hash_payload.1,
        },
        args,
        &schedule_to_user(&schedule.path),
        get_owner_from_path(&schedule.path),
        Some(next),
        Some(schedule.path),
        None,
    )
    .await?;
    Ok(tx)
}

async fn check_schedule_script<'c>(
    db: &mut Transaction<'c, Postgres>,
    script_path: Option<String>,
    script_hash: Option<i64>,
) -> Result<(ScriptHash, String)> {
    if script_hash.is_none() && script_path.is_none() {
        return Err(error::Error::BadRequest(
            "at least one of script_hash or script_path need to be defined".to_string(),
        ));
    }
    if script_hash.is_some() && script_path.is_some() {
        return Err(error::Error::BadRequest(
            "script_hash and script_path cannot be defined at the same time".to_string(),
        ));
    }
    if let Some(hash) = script_hash {
        let path = jobs::get_path_for_hash(db, hash).await?;
        Ok((ScriptHash(hash), path))
    } else {
        let path = script_path.unwrap();
        Ok((jobs::get_latest_hash_for_path(db, &path).await?, path))
    }
}

async fn create_schedule(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Json(ns): Json<NewSchedule>,
) -> Result<String> {
    cron::Schedule::from_str(&ns.schedule).map_err(|e| error::Error::BadRequest(e.to_string()))?;
    let mut tx = user_db.begin(&authed).await?;

    let script_hash_payload =
        check_schedule_script(&mut tx, ns.script_path.clone(), ns.script_hash).await?;
    let schedule = sqlx::query_as!(Schedule,
        "INSERT INTO schedule (path, schedule, edited_by, script_path, script_hash, args) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
        ns.path,
        ns.schedule,
        &authed.username,
        ns.script_path,
        ns.script_hash,
        ns.args
    )
    .fetch_one(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &authed.username,
        "schedule.create",
        ActionKind::Create,
        Some(&ns.path.to_string()),
        Some(
            [
                Some(("schedule", ns.schedule.as_str())),
                ns.script_path
                    .as_ref()
                    .map(|path| ("script_path", &path[..])),
                ns.script_hash
                    .map(|x| ScriptHash(x).to_string())
                    .as_ref()
                    .map(|hash| ("script_hash", &hash[..])),
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
    )
    .await?;

    let tx = push_scheduled_job(tx, schedule, script_hash_payload).await?;
    tx.commit().await?;
    Ok(ns.path.to_string())
}

#[derive(Deserialize)]
pub struct EditSchedule {
    pub schedule: String,
    pub script_path: Option<String>,
    pub script_hash: Option<i64>,
    pub args: Option<serde_json::Value>,
}

async fn clear_schedule<'c>(db: &mut Transaction<'c, Postgres>, path: &str) -> Result<()> {
    sqlx::query!("DELETE FROM queue WHERE schedule_path = $1", path)
        .execute(db)
        .await?;
    Ok(())
}

async fn edit_schedule(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
    Json(es): Json<EditSchedule>,
) -> Result<String> {
    let path = path.to_path();

    cron::Schedule::from_str(&es.schedule).map_err(|e| error::Error::BadRequest(e.to_string()))?;

    let mut tx = user_db.begin(&authed).await?;

    let script_hash_payload =
        check_schedule_script(&mut tx, es.script_path.clone(), es.script_hash).await?;

    clear_schedule(&mut tx, path).await?;
    let schedule = sqlx::query_as!(Schedule,
        "UPDATE schedule SET schedule = $1, script_path = $2, script_hash = $3, args = $4 WHERE path = $5 RETURNING *",
        es.schedule,
        es.script_path,
        es.script_hash,
        es.args,
        path
    )
    .fetch_one(&mut tx)
    .await?;

    if schedule.enabled {
        tx = push_scheduled_job(tx, schedule, script_hash_payload).await?;
    }

    audit_log(
        &mut tx,
        &authed.username,
        "schedule.edit",
        ActionKind::Update,
        Some(&path.to_string()),
        Some(
            [
                Some(("schedule", es.schedule.as_str())),
                es.script_path
                    .as_ref()
                    .map(|path| ("script_path", &path[..])),
                es.script_hash
                    .map(|x| ScriptHash(x).to_string())
                    .as_ref()
                    .map(|hash| ("script_hash", &hash[..])),
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
    )
    .await?;

    tx.commit().await?;
    Ok(path.to_string())
}

async fn list_schedule(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Query(pagination): Query<Pagination>,
) -> JsonResult<Vec<Schedule>> {
    let (per_page, offset) = crate::utils::paginate(pagination);
    let mut tx = user_db.begin(&authed).await?;

    let rows = sqlx::query_as!(
        Schedule,
        "SELECT * FROM schedule ORDER BY edited_at desc LIMIT $1 OFFSET $2",
        per_page as i64,
        offset as i64
    )
    .fetch_all(&mut tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

pub async fn get_schedule_opt<'c>(
    db: &mut Transaction<'c, Postgres>,
    path: &str,
) -> Result<Option<Schedule>> {
    let schedule_opt = sqlx::query_as!(Schedule, "SELECT * FROM schedule WHERE path = $1", path)
        .fetch_optional(db)
        .await?;
    Ok(schedule_opt)
}
async fn get_schedule(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
) -> JsonResult<Schedule> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    let schedule_o = get_schedule_opt(&mut tx, path).await?;
    let schedule = crate::utils::not_found_if_none(schedule_o, "Schedule", path)?;
    tx.commit().await?;
    Ok(Json(schedule))
}

#[derive(Deserialize)]
pub struct PreviewPayload {
    pub schedule: String,
}

pub async fn preview_schedule(
    Json(PreviewPayload { schedule }): Json<PreviewPayload>,
) -> JsonResult<Vec<DateTime<chrono::Utc>>> {
    let schedule =
        cron::Schedule::from_str(&schedule).map_err(|e| error::Error::BadRequest(e.to_string()))?;
    let upcoming: Vec<DateTime<chrono::Utc>> = schedule.upcoming(Utc).take(10).collect();
    Ok(Json(upcoming))
}

#[derive(Deserialize)]
pub struct SetEnabled {
    pub enabled: bool,
}

pub async fn set_enabled(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
    Json(SetEnabled { enabled }): Json<SetEnabled>,
) -> Result<String> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    let schedule_o = sqlx::query_as!(
        Schedule,
        "UPDATE schedule SET enabled = $1 WHERE path = $2 RETURNING *",
        enabled,
        path
    )
    .fetch_optional(&mut tx)
    .await?;

    let schedule = crate::utils::not_found_if_none(schedule_o, "Schedule", path)?;

    clear_schedule(&mut tx, path).await?;

    if enabled {
        let script_hash_payload =
            check_schedule_script(&mut tx, schedule.script_path.clone(), schedule.script_hash)
                .await?;

        tx = push_scheduled_job(tx, schedule, script_hash_payload).await?;
    }
    audit_log(
        &mut tx,
        &authed.username,
        "schedule.setenabled",
        ActionKind::Update,
        Some(path),
        Some([("enabled", enabled.to_string().as_ref())].into()),
    )
    .await?;
    tx.commit().await?;
    Ok(format!(
        "succesfully updated schedule at path {} to status {}",
        path, enabled
    ))
}

fn schedule_to_user(path: &str) -> String {
    format!("schedule-{}", path.replace('/', "-"))
}
