/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use std::sync::Arc;

use crate::{
    audit::{audit_log, ActionKind},
    db::{UserDB, DB},
    error::{Error, JsonResult, Result},
    users::{get_email_from_username, Authed},
    utils::StripPath,
};
use axum::{
    extract::{Extension, Path},
    routing::{delete, get, post},
    Json, Router,
};
use hyper::StatusCode;

use magic_crypt::{MagicCrypt256, MagicCryptTrait};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};

pub fn make_service() -> Router {
    Router::new()
        .route("/list", get(list_variables))
        .route("/list_reserved", get(list_reserved_variables))
        .route("/get/*path", get(get_variable))
        .route("/update/*path", post(update_variable))
        .route("/delete/*path", delete(delete_variable))
        .route("/create", post(create_variable))
}

#[derive(Serialize, Clone)]

pub struct ReservedVariable {
    pub name: String,
    pub value: String,
    pub description: String,
}

#[derive(Serialize)]

pub struct DecryptedVariable {
    pub path: String,
    pub name: String,
    pub value: String,
    pub is_secret: bool,
    pub extra_perms: serde_json::Value,
}

#[derive(Serialize)]

pub struct ListableVariable {
    pub path: String,
    pub name: String,
    pub value: Option<String>,
    pub is_secret: bool,
    pub extra_perms: serde_json::Value,
}

impl From<DecryptedVariable> for ListableVariable {
    fn from(d: DecryptedVariable) -> Self {
        ListableVariable {
            path: d.path,
            name: d.name,
            value: if d.is_secret { None } else { Some(d.value) },
            is_secret: d.is_secret,
            extra_perms: d.extra_perms,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateDecryptedVariable {
    pub path: String,
    pub value: String,
    pub is_secret: bool,
}

#[derive(Deserialize)]
struct EditDecryptedVariable {
    path: Option<String>,
    value: Option<String>,
    is_secret: Option<bool>,
}

#[derive(FromRow)]
struct EncryptedVariable {
    path: String,
    value: String,
    is_secret: bool,
    extra_perms: serde_json::Value,
}

pub async fn get_all_variables<'c>(
    db: &mut Transaction<'c, Postgres>,
    mc: &Arc<MagicCrypt256>,
) -> Result<Vec<DecryptedVariable>> {
    let rows = sqlx::query_as!(EncryptedVariable, "SELECT * from variable ORDER BY path")
        .fetch_all(db)
        .await?;

    Ok(rows
        .into_iter()
        .map(|e| decrypt(mc, e))
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn get_reserved_variables(
    token: &str,
    email: &str,
    username: &str,
    job_id: &str,
) -> [ReservedVariable; 4] {
    [
        ReservedVariable {
            name: "WM_TOKEN".to_string(),
            value: token.to_string(),
            description: "Token ephemeral to the current script with equal permission to the permission of the run (Usable as a bearer token)".to_string()
        },
        ReservedVariable {
            name: "WM_EMAIL".to_string(),
            value: email.to_string(),
            description: "Email of the user that executed the current script".to_string()
        },
        ReservedVariable {
            name: "WM_USERNAME".to_string(),
            value: username.to_string(),
            description: "Username of the user that executed the current script".to_string()
        },
        ReservedVariable {
            name: "WM_JOB_ID".to_string(),
            value: job_id.to_string(),
            description: "Job id of the current script".to_string()
        },
    ]
}

async fn list_reserved_variables(
    Extension(db): Extension<DB>,
    Authed { username, .. }: Authed,
) -> JsonResult<Vec<ReservedVariable>> {
    Ok(Json(
        get_reserved_variables(
            "q1A0qcPuO00yxioll7iph76N9CJDqn",
            &get_email_from_username(&username, &db).await?.unwrap(),
            &username,
            "017e0ad5-f499-73b6-5488-92a61c5196dd",
        )
        .to_vec(),
    ))
}

async fn list_variables(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(mc): Extension<Arc<MagicCrypt256>>,
) -> JsonResult<Vec<ListableVariable>> {
    let mut tx = user_db.begin(&authed).await?;
    let r = get_all_variables(&mut tx, &mc)
        .await?
        .into_iter()
        .map(From::from)
        .collect();

    tx.commit().await?;
    Ok(Json(r))
}

async fn get_variable(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(mc): Extension<Arc<MagicCrypt256>>,

    Path(path): Path<StripPath>,
) -> JsonResult<ListableVariable> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    let variable_o = sqlx::query_as!(
        EncryptedVariable,
        "SELECT * from variable WHERE path = $1",
        path
    )
    .fetch_optional(&mut tx)
    .await?;

    let variable = crate::utils::not_found_if_none(variable_o, "Variable", &path)?;
    tx.commit().await?;

    Ok(Json(From::from(decrypt(&mc, variable)?)))
}

async fn create_variable(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(mc): Extension<Arc<MagicCrypt256>>,
    Json(variable): Json<CreateDecryptedVariable>,
) -> Result<(StatusCode, String)> {
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query!(
        "INSERT INTO variable
            (path, value, is_secret)
            VALUES ($1, $2, $3)",
        variable.path,
        encrypt(&mc, variable.value),
        variable.is_secret,
    )
    .execute(&mut tx)
    .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "variables.create",
        ActionKind::Create,
        Some(&variable.path),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        format!("variable {} created", variable.path),
    ))
}

async fn delete_variable(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(db): Extension<DB>,
    Path(path): Path<StripPath>,
) -> Result<String> {
    let path = path.to_path();
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query!("DELETE FROM variable WHERE path = $1", path)
        .execute(&db)
        .await?;
    audit_log(
        &mut tx,
        &authed.username,
        "variables.delete",
        ActionKind::Delete,
        Some(path),
        None,
    )
    .await?;

    tx.commit().await?;

    Ok(format!("variable {} deleted", path))
}

async fn update_variable(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
    Extension(db): Extension<DB>,
    Extension(mc): Extension<Arc<MagicCrypt256>>,
    Path(path): Path<StripPath>,
    Json(ns): Json<EditDecryptedVariable>,
) -> Result<String> {
    use sql_builder::prelude::*;

    let path = path.to_path();

    let mut sqlb = SqlBuilder::update_table("variable");
    sqlb.and_where("path = ?".bind(&path));
    if let Some(npath) = &ns.path {
        sqlb.set_str("path", npath);
    }
    if let Some(nvalue) = ns.value {
        sqlb.set_str("value", &encrypt(&mc, nvalue));
    }
    if let Some(nbool) = ns.is_secret {
        if !nbool {
            return Err(Error::BadRequest(
                "A variable can not be updated to be non secret".to_owned(),
            ));
        }
        sqlb.set_str("is_secret", nbool);
    }
    let sql = sqlb.sql().map_err(|e| Error::InternalErr(e.to_string()))?;
    let mut tx = user_db.begin(&authed).await?;

    sqlx::query(&sql).execute(&db).await?;
    audit_log(
        &mut tx,
        &authed.username,
        "variables.update",
        ActionKind::Update,
        Some(path),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("variable {} updated (npath: {:?})", path, ns.path))
}

fn decrypt(mc: &MagicCrypt256, variable: EncryptedVariable) -> Result<DecryptedVariable> {
    Ok(DecryptedVariable {
        name: path_to_name(&variable.path),
        path: variable.path,
        value: mc
            .decrypt_base64_to_string(variable.value)
            .map_err(|e| Error::InternalErr(e.to_string()))?,
        is_secret: variable.is_secret,
        extra_perms: variable.extra_perms,
    })
}

pub fn encrypt(mc: &MagicCrypt256, value: String) -> String {
    mc.encrypt_str_to_base64(value)
}

fn path_to_name(path: &str) -> String {
    path.to_uppercase().replace("/", "_")
}
