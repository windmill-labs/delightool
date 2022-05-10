/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use crate::{
    audit::{audit_log, ActionKind},
    db::UserDB,
    error::{Error, JsonResult, Result},
    users::Authed,
    utils::{require_admin, StripPath},
};
use axum::{
    extract::{Extension, Path},
    routing::{delete, get, post},
    Json, Router,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub fn make_service() -> Router {
    Router::new()
        .route("/list", get(list_resources))
        .route("/get/*path", get(get_resource))
        .route("/update/*path", post(update_resource))
        .route("/delete/*path", delete(delete_resource))
        .route("/create", post(create_resource))
        .route("/type/list", get(list_resource_types))
        .route("/type/get/:name", get(get_resource_type))
        .route("/type/update/:name", post(update_resource_type))
        .route("/type/delete/:name", delete(delete_resource_type))
        .route("/type/create", post(create_resource_type))
}

#[derive(Serialize, Deserialize)]
pub struct ResourceType {
    pub name: String,
    pub schema: Option<serde_json::Value>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct EditResourceType {
    pub schema: Option<serde_json::Value>,
    pub description: Option<String>,
}

#[derive(FromRow, Serialize, Deserialize)]
pub struct Resource {
    pub path: String,
    pub value: Option<serde_json::Value>,
    pub description: Option<String>,
    pub resource_type: String,
    pub extra_perms: serde_json::Value,
}

#[derive(Deserialize)]
pub struct CreateResource {
    pub path: String,
    pub value: Option<serde_json::Value>,
    pub description: Option<String>,
    pub resource_type: String,
}
#[derive(Deserialize)]
struct EditResource {
    path: Option<String>,
    description: Option<String>,
    value: Option<serde_json::Value>,
}

async fn list_resources(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
) -> JsonResult<Vec<Resource>> {
    let mut tx = user_db.begin(&authed).await?;

    let rows = sqlx::query_as!(
        Resource,
        "SELECT path, null::JSONB as value, description, resource_type, extra_perms FROM resource ORDER BY path"
    )
    .fetch_all(&mut tx)
    .await?;
    tx.commit().await?;

    Ok(Json(rows))
}

async fn get_resource(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
) -> JsonResult<Resource> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    let resource_o = sqlx::query_as!(
        Resource,
        "SELECT * from resource WHERE path = $1",
        path.to_owned()
    )
    .fetch_optional(&mut tx)
    .await?;
    tx.commit().await?;

    let resource = crate::utils::not_found_if_none(resource_o, "Resource", path)?;
    Ok(Json(resource))
}

async fn create_resource(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Json(resource): Json<CreateResource>,
) -> Result<(StatusCode, String)> {
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query!(
        "INSERT INTO resource
            (path, value, description, resource_type)
            VALUES ($1, $2, $3, $4)",
        resource.path,
        resource.value,
        resource.description,
        resource.resource_type,
    )
    .execute(&mut tx)
    .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resources.create",
        ActionKind::Create,
        Some(&resource.path),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        format!("resource {} created", resource.path),
    ))
}

async fn delete_resource(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
) -> Result<String> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query!("DELETE FROM resource WHERE path = $1", path)
        .execute(&mut tx)
        .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resources.delete",
        ActionKind::Delete,
        Some(path),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("resource {} deleted", path))
}

async fn update_resource(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(path): Path<StripPath>,
    Json(ns): Json<EditResource>,
) -> Result<String> {
    use sql_builder::prelude::*;

    let path = path.to_path();

    let mut sqlb = SqlBuilder::update_table("resource");
    sqlb.and_where("path = ?".bind(&path));
    if let Some(npath) = &ns.path {
        sqlb.set_str("path", npath);
    }
    if let Some(nvalue) = ns.value {
        sqlb.set_str("value", nvalue.to_string());
    }
    if let Some(ndesc) = ns.description {
        sqlb.set_str("description", ndesc);
    }
    let mut tx = user_db.begin(&authed).await?;

    let sql = sqlb.sql().map_err(|e| Error::InternalErr(e.to_string()))?;
    sqlx::query(&sql).execute(&mut tx).await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resources.update",
        ActionKind::Update,
        Some(path),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("resource {} updated (npath: {:?})", path, ns.path))
}

async fn list_resource_types(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
) -> JsonResult<Vec<ResourceType>> {
    let mut tx = user_db.begin(&authed).await?;

    let rows = sqlx::query_as!(ResourceType, "SELECT * from resource_type ORDER BY name")
        .fetch_all(&mut tx)
        .await?;
    tx.commit().await?;

    Ok(Json(rows.into_iter().collect()))
}

async fn get_resource_type(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
) -> JsonResult<ResourceType> {
    let mut tx = user_db.begin(&authed).await?;

    let resource_type_o = sqlx::query_as!(
        ResourceType,
        "SELECT * from resource_type WHERE name = $1",
        name
    )
    .fetch_optional(&mut tx)
    .await?;
    tx.commit().await?;

    let resource_type = crate::utils::not_found_if_none(resource_type_o, "ResourceType", name)?;
    Ok(Json(resource_type))
}

async fn create_resource_type(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Json(resource_type): Json<ResourceType>,
) -> Result<(StatusCode, String)> {
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query!(
        "INSERT INTO resource_type
            (name, schema, description)
            VALUES ($1, $2, $3)",
        resource_type.name,
        resource_type.schema,
        resource_type.description,
    )
    .execute(&mut tx)
    .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resource_types.create",
        ActionKind::Create,
        Some(&resource_type.name),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        format!("resource_type {} created", resource_type.name),
    ))
}

async fn delete_resource_type(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
) -> Result<String> {
    let mut tx = user_db.begin(&authed).await?;
    require_admin(&mut tx, &authed.username).await?;

    sqlx::query!("DELETE FROM resource_type WHERE name = $1", name)
        .execute(&mut tx)
        .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resource_types.delete",
        ActionKind::Delete,
        Some(&name),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("resource_type {} deleted", name))
}

async fn update_resource_type(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Path(name): Path<String>,
    Json(ns): Json<EditResourceType>,
) -> Result<String> {
    use sql_builder::prelude::*;

    let mut sqlb = SqlBuilder::update_table("resource_type");
    if let Some(nschema) = ns.schema {
        sqlb.set_str("schema", nschema);
    }
    if let Some(ndesc) = ns.description {
        sqlb.set_str("description", ndesc);
    }
    let sql = sqlb.sql().map_err(|e| Error::InternalErr(e.to_string()))?;
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query(&sql).execute(&mut tx).await?;
    audit_log(
        &mut tx,
        &authed.username,
        "resource_types.update",
        ActionKind::Update,
        Some(&name),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("resource_type {} updated", name))
}
