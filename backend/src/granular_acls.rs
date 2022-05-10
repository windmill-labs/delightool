/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use crate::{
    db::UserDB,
    error::{Error, JsonResult, Result},
    users::Authed,
    utils::StripPath,
};
use axum::{
    extract::{Extension, Path},
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};

pub fn make_service() -> Router {
    Router::new()
        .route("/get/*path", get(get_granular_acls))
        .route("/add/*path", post(add_granular_acl))
        .route("/remove/*path", post(remove_granular_acl))
}

#[derive(Serialize, Deserialize)]
pub struct GranularAcl {
    pub owner: String,
    pub write: Option<bool>,
}

async fn add_granular_acl(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
    Json(GranularAcl { owner, write }): Json<GranularAcl>,
) -> Result<String> {
    let path = path.to_path();
    let (kind, path) = path
        .split_once('/')
        .ok_or_else(|| Error::BadRequest("Invalid path or kind".to_string()))?;
    let mut tx = user_db.begin(&authed).await?;

    let obj_o = sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "UPDATE {} SET extra_perms = jsonb_set(extra_perms, '{{\"{}\"}}', to_jsonb($1), true) WHERE path = $2 RETURNING extra_perms",
        kind, owner
    ))
    .bind(write.unwrap_or(false))
    .bind(path)
    .fetch_optional(&mut tx)
    .await?;

    let _ = crate::utils::not_found_if_none(obj_o, &kind, &path)?;
    tx.commit().await?;

    Ok("Successfully modified granular acl".to_string())
}

async fn remove_granular_acl(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
    Json(GranularAcl { owner, write: _ }): Json<GranularAcl>,
) -> Result<String> {
    let path = path.to_path();
    let (kind, path) = path
        .split_once('/')
        .ok_or_else(|| Error::BadRequest("Invalid path or kind".to_string()))?;
    let mut tx = user_db.begin(&authed).await?;

    let obj_o = sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "UPDATE {} SET extra_perms = extra_perms - $1 WHERE path = $2 RETURNING extra_perms",
        kind
    ))
    .bind(owner)
    .bind(path)
    .fetch_optional(&mut tx)
    .await?;

    let _ = crate::utils::not_found_if_none(obj_o, &kind, &path)?;
    tx.commit().await?;

    Ok("Successfully removed granular acl".to_string())
}

async fn get_granular_acls(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
) -> JsonResult<serde_json::Value> {
    let path = path.to_path();
    let (kind, path) = path
        .split_once('/')
        .ok_or_else(|| Error::BadRequest("Invalid path or kind".to_string()))?;

    let mut tx = user_db.begin(&authed).await?;

    let obj_o = sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "SELECT extra_perms from {} WHERE path = $1",
        kind
    ))
    .bind(path)
    .fetch_optional(&mut tx)
    .await?;

    let obj = crate::utils::not_found_if_none(obj_o, &kind, &path)?;
    tx.commit().await?;

    Ok(Json(obj))
}
