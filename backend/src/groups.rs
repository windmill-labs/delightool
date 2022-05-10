/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use crate::{
    audit::{audit_log, ActionKind},
    db::{UserDB, DB},
    error::{JsonResult, Result},
    users::Authed,
    utils::Pagination,
};
use axum::{
    extract::{Extension, Path, Query},
    routing::{delete, get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};

pub fn make_service() -> Router {
    Router::new()
        .route("/list", get(list_groups))
        .route("/listnames", get(list_group_names))
        .route("/create", post(create_group))
        .route("/get/:name", get(get_group))
        .route("/update/:name", post(update_group))
        .route("/delete/:name", delete(delete_group))
        .route("/adduser/:name", post(add_user))
        .route("/removeuser/:name", post(remove_user))
}

#[derive(FromRow, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub summary: Option<String>,
    pub extra_perms: serde_json::Value,
}

#[derive(Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub summary: Option<String>,
    pub members: Vec<String>,
    pub extra_perms: serde_json::Value,
}

#[derive(Deserialize)]
pub struct EditGroup {
    pub summary: Option<String>,
}

#[derive(Deserialize)]
pub struct Username {
    pub username: String,
}

async fn list_groups(
    Extension(db): Extension<DB>,
    Query(pagination): Query<Pagination>,
) -> JsonResult<Vec<Group>> {
    let (per_page, offset) = crate::utils::paginate(pagination);

    let rows = sqlx::query_as!(
        Group,
        "SELECT * FROM group_ ORDER BY name desc LIMIT $1 OFFSET $2",
        per_page as i64,
        offset as i64
    )
    .fetch_all(&db)
    .await?;

    Ok(Json(rows))
}

async fn list_group_names(Extension(db): Extension<DB>) -> JsonResult<Vec<String>> {
    let rows = sqlx::query_scalar!("SELECT name FROM group_ ORDER BY name desc")
        .fetch_all(&db)
        .await?;

    Ok(Json(rows))
}

async fn create_group(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Json(ng): Json<Group>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query_as!(
        Group,
        "INSERT INTO group_ VALUES ($1, $2)",
        ng.name,
        ng.summary,
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &authed.username,
        "group.create",
        ActionKind::Create,
        Some(&ng.name.to_string()),
        None,
    )
    .await?;

    tx.commit().await?;
    Ok(format!("Created group {}", ng.name))
}

pub async fn get_group_opt<'c>(
    db: &mut Transaction<'c, Postgres>,
    name: &str,
) -> Result<Option<Group>> {
    let group_opt = sqlx::query_as!(Group, "SELECT * FROM group_ WHERE name = $1", name)
        .fetch_optional(db)
        .await?;
    Ok(group_opt)
}

async fn get_group(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
) -> JsonResult<GroupInfo> {
    let mut tx = user_db.begin(&authed).await?;

    let group =
        crate::utils::not_found_if_none(get_group_opt(&mut tx, &name).await?, "Group", &name)?;

    let members = sqlx::query_scalar!(
        "SELECT  usr.username  
            FROM usr_to_group LEFT JOIN usr ON usr_to_group.usr = usr.username 
            WHERE group_ = $1",
        name
    )
    .fetch_all(&mut tx)
    .await?;

    tx.commit().await?;
    Ok(Json(GroupInfo {
        name: group.name,
        summary: group.summary,
        members,
        extra_perms: group.extra_perms,
    }))
}

async fn delete_group(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    crate::utils::not_found_if_none(get_group_opt(&mut tx, &name).await?, "Group", &name)?;

    sqlx::query!("DELETE FROM usr_to_group WHERE group_ = $1", name)
        .execute(&mut tx)
        .await?;
    sqlx::query!("DELETE FROM group_ WHERE name = $1", name)
        .execute(&mut tx)
        .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "group.delete",
        ActionKind::Delete,
        Some(&name.to_string()),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(format!("delete group at name {}", name))
}

async fn update_group(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
    Json(eg): Json<EditGroup>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    crate::utils::not_found_if_none(get_group_opt(&mut tx, &name).await?, "Group", &name)?;

    sqlx::query_as!(
        Group,
        "UPDATE group_ SET summary = $1 WHERE name = $2",
        eg.summary,
        name,
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &authed.username,
        "group.edit",
        ActionKind::Update,
        Some(&name.to_string()),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(format!("Edited group {}", name))
}

async fn add_user(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
    Json(Username {
        username: user_username,
    }): Json<Username>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    crate::utils::not_found_if_none(get_group_opt(&mut tx, &name).await?, "Group", &name)?;

    sqlx::query_as!(
        Group,
        "INSERT INTO usr_to_group VALUES ($1, $2)",
        user_username,
        name,
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &authed.username,
        "group.adduser",
        ActionKind::Update,
        Some(&name.to_string()),
        Some([("user", user_username.as_str())].into()),
    )
    .await?;
    tx.commit().await?;
    Ok(format!("Added {} to group {}", user_username, name))
}

async fn remove_user(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
    Json(Username {
        username: user_username,
    }): Json<Username>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;

    crate::utils::not_found_if_none(get_group_opt(&mut tx, &name).await?, "Group", &name)?;

    sqlx::query_as!(
        Group,
        "DELETE FROM usr_to_group WHERE usr = $1 AND group_ = $2",
        user_username,
        name,
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &authed.username,
        "group.removeuser",
        ActionKind::Update,
        Some(&name.to_string()),
        Some([("user", user_username.as_str())].into()),
    )
    .await?;

    tx.commit().await?;
    Ok(format!("Removed {} to group {}", user_username, name))
}
