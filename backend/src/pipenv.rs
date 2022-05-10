/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use crate::{
    audit::{audit_log, ActionKind},
    db::{UserDB, DB},
    error::{JsonResult, Result},
    jobs::JobPayload,
    users::{owner_to_token_owner, Authed},
    utils::{require_admin, Pagination},
};
use axum::{
    extract::{Extension, Path, Query},
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub const DEFAULT_PY_V: &str = "3.10";
pub const PIPFILE_PRELUDE: &str = include_str!("../../Pipfile");

pub fn make_service() -> Router {
    let pipenv_const = Json(PipenvConsts {
        python_version: DEFAULT_PY_V.to_string(),
        dependencies: PIPFILE_PRELUDE
            .split_once("[packages]\n")
            .unwrap()
            .1
            .split('\n')
            .filter(|x| !x.is_empty())
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
    });
    Router::new()
        .route("/getprelude", get(|| async move { pipenv_const.clone() }))
        .route("/list", get(list_pipenv))
        .route("/get/:id", get(get_pipenv))
        .route("/getlast", get(get_last_pipenv))
        .route("/add", post(add_pipenv))
}

#[derive(FromRow, Serialize, Deserialize, Debug)]
pub struct Pipenv {
    pub id: i32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
    pub python_version: Option<String>,
    pub dependencies: Vec<String>,
    pub pipfile_lock: Option<String>,
    pub job_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct AddPipenv {
    pub python_version: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct PipenvConsts {
    pub python_version: String,
    pub dependencies: Vec<String>,
}

async fn list_pipenv(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Query(pagination): Query<Pagination>,
) -> JsonResult<Vec<Pipenv>> {
    let mut tx = user_db.begin(&authed).await?;

    let (per_page, offset) = crate::utils::paginate(pagination);

    let rows = sqlx::query_as!(
        Pipenv,
        "SELECT id, timestamp, created_by, python_version, dependencies, \
         CAST (((pipfile_lock <> '') IS TRUE) AS TEXT) as pipfile_lock, job_id \
         FROM pipenv ORDER BY id desc LIMIT $1 OFFSET $2",
        per_page as i64,
        offset as i64
    )
    .fetch_all(&mut tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

pub async fn pipenv_by_id(db: &DB, id: i32) -> Result<Option<Pipenv>> {
    Ok(
        sqlx::query_as!(Pipenv, "SELECT * FROM pipenv WHERE id = $1", id)
            .fetch_optional(db)
            .await?,
    )
}
async fn get_pipenv(Extension(db): Extension<DB>, Path(id): Path<i32>) -> JsonResult<Pipenv> {
    let pipenv =
        crate::utils::not_found_if_none(pipenv_by_id(&db, id).await?, "Pipenv", id.to_string())?;
    Ok(Json(pipenv))
}

pub async fn set_pipenv_lock(db: &DB, content: String, id: i32) -> Result<()> {
    sqlx::query!(
        "UPDATE pipenv SET pipfile_lock = $1 WHERE id = $2",
        content,
        id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_job_id(db: &DB, job_id: Uuid, id: i32) -> Result<()> {
    sqlx::query!("UPDATE pipenv SET job_id = $1 WHERE id = $2", job_id, id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn last_pipenv(db: &DB) -> Result<Option<Pipenv>> {
    Ok(sqlx::query_as!(
        Pipenv,
        "SELECT * FROM pipenv WHERE id = (select max(id) from pipenv)"
    )
    .fetch_optional(db)
    .await?)
}

async fn get_last_pipenv(Extension(db): Extension<DB>) -> JsonResult<Option<Pipenv>> {
    let pipenv = last_pipenv(&db).await?;
    Ok(Json(pipenv))
}

pub async fn pipenv_last_id_valid(db: &DB) -> Result<Option<i32>> {
    Ok(sqlx::query_scalar!(
        "SELECT id FROM pipenv WHERE id = (select max(id) from pipenv WHERE pipfile_lock IS NOT NULL)"
    )
    .fetch_optional(db)
    .await?)
}

pub async fn insert_pipenv(db: &DB, email: String, add_pipenv: AddPipenv) -> Result<i32> {
    Ok(sqlx::query_scalar!(
        "INSERT INTO pipenv
            (created_by, python_version, dependencies)
            VALUES ($1, $2, $3) RETURNING id",
        email,
        add_pipenv.python_version,
        &add_pipenv.dependencies
    )
    .fetch_one(db)
    .await?)
}
async fn add_pipenv(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(db): Extension<DB>,
    Json(add_pipenv): Json<AddPipenv>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;
    require_admin(&mut tx, &authed.username).await?;
    let pipenv_id = insert_pipenv(&db, authed.username.to_string(), add_pipenv).await?;
    audit_log(
        &mut tx,
        &authed.username,
        "pipenv.create",
        ActionKind::Create,
        Some(&pipenv_id.to_string()),
        None,
    )
    .await?;
    let (job_id, tx) = crate::jobs::push(
        tx,
        &JobPayload::Dependencies(pipenv_id),
        None,
        &authed.username,
        owner_to_token_owner(&authed.username, false),
        None,
        None,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(job_id.to_string())
}
