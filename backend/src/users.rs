/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use std::{sync::Arc, time::Duration};

use crate::{
    audit::{audit_log, ActionKind},
    db::{UserDB, DB},
    error::{Error, JsonResult, Result},
    utils::require_admin,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    async_trait,
    extract::{Extension, FromRequest, Path, RequestParts},
    http,
    routing::{delete, get, post},
    Json, Router,
};
use hyper::StatusCode;
use rand::rngs::OsRng;
use retainer::Cache;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tower_cookies::{Cookie, Cookies};
use tracing::Span;

const TTL_TOKEN_CACHE_S: u64 = 60 * 5; // 5 minutes
pub const TTL_TOKEN_DB_H: u32 = 48;

const COOKIE_NAME: &str = "token";
const COOKIE_PATH: &str = "/";

pub fn make_service() -> Router {
    Router::new()
        .route("/list", get(list_users))
        .route("/listusernames", get(list_usernames))
        .route("/create", post(create_user))
        .route("/update/:user", post(update_user))
        .route("/delete/:user", delete(delete_user))
        .route("/setpassword", post(set_password))
        .route("/logout", post(logout))
        .route("/whoami", get(whoami))
        .route("/whois/:email", get(whois))
        .route("/tokens/create", post(create_token))
        .route("/tokens/delete/:token_prefix", delete(delete_token))
        .route("/tokens/list", get(list_tokens))
}

pub fn make_unauthed_service() -> Router {
    Router::new().route("/login", post(login))
}

pub struct AuthCache {
    cache: Cache<String, Authed>,
    db: DB,
}

impl AuthCache {
    pub fn new(db: DB) -> Self {
        AuthCache {
            cache: Cache::new(),
            db,
        }
    }

    pub async fn get_user(&self, token: &str) -> Option<Authed> {
        let key = token.to_owned();
        let s = self.cache.get(&key).await.map(|c| c.to_owned());
        match s {
            a @ Some(_) => a,
            None => {
                let owner_o =
                    sqlx::query_scalar!("SELECT owner FROM token WHERE token = $1", token)
                        .fetch_optional(&self.db)
                        .await
                        .ok()
                        .flatten();

                if let Some((prefix, name)) =
                    owner_o.as_ref().and_then(|owner| owner.split_once('/'))
                {
                    let authed = {
                        if prefix == "u" {
                            let is_admin = sqlx::query_scalar!(
                                "SELECT is_admin FROM usr where username = $1",
                                name
                            )
                            .fetch_one(&self.db)
                            .await
                            .ok()
                            .unwrap_or(false);
                            let groups = get_groups_for_user(&name, &self.db)
                                .await
                                .ok()
                                .unwrap_or_default();
                            let username = name.to_string();

                            Authed {
                                username,
                                is_admin,
                                groups,
                            }
                        } else {
                            Authed {
                                username: format!("group-{}", name),
                                is_admin: false,
                                groups: vec![name.to_string()],
                            }
                        }
                    };
                    self.cache
                        .insert(key, authed.clone(), Duration::from_secs(TTL_TOKEN_CACHE_S))
                        .await;
                    Some(authed)
                } else {
                    None
                }
            }
        }
    }

    pub async fn logout(&self, username: &str) -> Result<()> {
        let token = sqlx::query_scalar!(
            "SELECT token FROM token WHERE owner = $1",
            &owner_to_token_owner(username, false)
        )
        .fetch_one(&self.db)
        .await?;

        let _ = &self.cache.remove(&token).await;
        Ok(())
    }

    pub async fn monitor(&self) {
        self.cache.monitor(20, 0.25, Duration::from_secs(10)).await;
    }
}

async fn extract_token<B: Send>(req: &mut RequestParts<B>) -> Option<String> {
    let auth_header = req
        .headers()
        .and_then(|headers| headers.get(http::header::AUTHORIZATION))
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    match auth_header {
        Some(x) => Some(x.to_owned()),
        None => Extension::<Cookies>::from_request(req)
            .await
            .ok()
            .and_then(|cookies| cookies.get(COOKIE_NAME).map(|c| c.value().to_owned())),
    }
}

#[derive(Clone, Debug)]
pub struct Tokened {
    pub token: String,
}

#[async_trait]
impl<B> FromRequest<B> for Tokened
where
    B: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        let token_o = extract_token(req).await;
        if let Some(token) = token_o {
            Ok(Self { token })
        } else {
            Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_owned()))
        }
    }
}

#[derive(Clone)]
pub struct Authed {
    pub username: String,
    pub is_admin: bool,
    pub groups: Vec<String>,
}

#[async_trait]
impl<B> FromRequest<B> for Authed
where
    B: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        let token_o = extract_token(req).await;

        if let Some(token) = token_o {
            if let Ok(Extension(cache)) = Extension::<Arc<AuthCache>>::from_request(req).await {
                if let Some(authed) = cache.get_user(&token).await {
                    Span::current().record("username", &authed.username.as_str());
                    return Ok(authed);
                }
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_owned()))
    }
}

#[derive(FromRow, Serialize)]
pub struct User {
    pub email: String,
    pub username: String,
    pub is_admin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub email: String,
    pub username: String,
    pub is_admin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed_at: chrono::DateTime<chrono::Utc>,
    pub groups: Vec<String>,
}

#[derive(Deserialize)]
pub struct NewUser {
    pub email: String,
    pub username: String,
    pub password: String,
    pub is_admin: bool,
}

#[derive(Deserialize)]
pub struct EditUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Deserialize)]
pub struct EditPassword {
    pub password: String,
}
#[derive(FromRow, Serialize)]
pub struct TruncatedToken {
    pub label: Option<String>,
    pub token_prefix: Option<String>,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct NewToken {
    pub label: Option<String>,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct Login {
    pub email_or_username: String,
    pub password: String,
}

async fn list_users(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
) -> JsonResult<Vec<User>> {
    let mut tx = user_db.begin(&authed).await?;
    let rows = sqlx::query_as!(User, "SELECT * from usr")
        .fetch_all(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

async fn list_usernames(
    authed: Authed,
    Extension(user_db): Extension<UserDB>,
) -> JsonResult<Vec<String>> {
    let mut tx = user_db.begin(&authed).await?;
    let rows = sqlx::query_scalar!("SELECT username from usr")
        .fetch_all(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

async fn logout(
    Tokened { token }: Tokened,
    cookies: Cookies,
    Extension(db): Extension<DB>,
    Extension(auth_cache): Extension<Arc<AuthCache>>,
    Authed { username, .. }: Authed,
) -> Result<String> {
    auth_cache.logout(&username).await?;
    let mut cookie = Cookie::new(COOKIE_NAME, "");
    cookie.set_path(COOKIE_PATH);
    cookies.remove(cookie);
    let mut tx = db.begin().await?;
    audit_log(
        &mut tx,
        &username,
        "users.logout",
        ActionKind::Delete,
        Some(&truncate_token(&token)),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(username)
}

async fn whoami(
    Extension(db): Extension<DB>,
    Authed { username, .. }: Authed,
) -> JsonResult<UserInfo> {
    let user = get_user(&username, &db).await?.unwrap();
    Ok(Json(user))
}

async fn get_user(username: &str, db: &DB) -> Result<Option<UserInfo>> {
    let user = sqlx::query_as!(User, "SELECT * FROM usr where username = $1", username)
        .fetch_optional(db)
        .await?;
    let groups = get_groups_for_user(username, db).await?;
    Ok(user.map(|usr| UserInfo {
        groups,
        email: usr.email,
        username: usr.username,
        is_admin: usr.is_admin,
        created_at: usr.created_at,
        last_accessed_at: usr.last_accessed_at,
    }))
}

async fn get_groups_for_user(username: &str, db: &DB) -> Result<Vec<String>> {
    let groups = sqlx::query_scalar!("SELECT group_ FROM usr_to_group where usr = $1", username)
        .fetch_all(db)
        .await?;
    Ok(groups)
}

async fn whois(Extension(db): Extension<DB>, Path(username): Path<String>) -> JsonResult<UserInfo> {
    let user_o = get_user(&username, &db).await?;
    let user = crate::utils::not_found_if_none(user_o, "User", username)?;
    Ok(Json(user))
}

async fn create_user(
    Authed { username, .. }: Authed,
    Extension(db): Extension<DB>,
    Extension(argon2): Extension<Arc<Argon2<'_>>>,
    Json(nu): Json<NewUser>,
) -> Result<(StatusCode, String)> {
    let mut tx = db.begin().await?;

    require_admin(&mut tx, &username).await?;

    sqlx::query!(
        "INSERT INTO usr
            (email, username, is_admin)
            VALUES ($1, $2, $3)",
        nu.email,
        nu.username,
        nu.is_admin
    )
    .execute(&mut tx)
    .await?;

    sqlx::query!(
        "INSERT INTO password
            (email, password_hash)
            VALUES ($1, $2)",
        nu.email,
        hash_password(argon2, nu.password)?
    )
    .execute(&mut tx)
    .await?;

    sqlx::query_as!(
        Group,
        "INSERT INTO usr_to_group (usr, group_) VALUES ($1, $2)",
        nu.username,
        "all",
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &username,
        "users.create",
        ActionKind::Create,
        Some(&nu.email),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        format!("user with email {} created", nu.email),
    ))
}

async fn update_user(
    Authed { username, .. }: Authed,
    Extension(db): Extension<DB>,
    Extension(argon2): Extension<Arc<Argon2<'_>>>,
    Path(username_to_update): Path<String>,
    Json(nu): Json<EditUser>,
) -> Result<String> {
    use sql_builder::prelude::*;
    let mut tx = db.begin().await?;

    require_admin(&mut tx, &username).await?;
    let email_to_update_o = sqlx::query_scalar!(
        "SELECT email FROM usr where username = $1",
        username_to_update
    )
    .fetch_optional(&db)
    .await?;

    let email_to_update =
        crate::utils::not_found_if_none(email_to_update_o, "User", &username_to_update)?;

    for t in &["usr", "password"] {
        sqlx::query(&format!("ALTER TABLE {} DISABLE TRIGGER ALL;", t))
            .execute(&mut tx)
            .await?;
    }

    if nu.email.is_some() || nu.is_admin.is_some() {
        let mut sqlb = SqlBuilder::update_table("usr");
        sqlb.and_where("email = ?".bind(&email_to_update));

        if let Some(nemail) = nu.email.clone() {
            sqlb.set_str("email", &nemail);
        }
        if let Some(nis_admin) = nu.is_admin {
            sqlb.set_str("is_admin", &nis_admin);
        }

        let sql = sqlb.sql().map_err(|e| Error::InternalErr(e.to_string()))?;
        sqlx::query(&sql).execute(&mut tx).await?;
    }

    if nu.email.is_some() || nu.password.is_some() {
        let mut sqlb = SqlBuilder::update_table("password");
        sqlb.and_where("email = ?".bind(&email_to_update));
        if let Some(npassword) = &nu.password {
            sqlb.set_str(
                "password_hash",
                &hash_password(argon2, npassword.to_owned())?,
            );
        }
        if let Some(nemail) = nu.email.clone() {
            sqlb.set_str("email", &nemail);
        }
        let sql = sqlb.sql().map_err(|e| Error::InternalErr(e.to_string()))?;
        sqlx::query(&sql).execute(&mut tx).await?;
    }

    for t in &["usr", "password"] {
        sqlx::query(&format!("ALTER TABLE {} ENABLE TRIGGER ALL;", t))
            .execute(&mut tx)
            .await?;
    }

    audit_log(
        &mut tx,
        &username,
        "users.update",
        ActionKind::Update,
        Some(&email_to_update),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(format!("email {} updated", email_to_update))
}

pub fn owner_to_token_owner(user: &str, is_group: bool) -> String {
    let prefix = if is_group { 'g' } else { 'u' };
    format!("{}/{}", prefix, user)
}

async fn delete_user(
    Authed { username, .. }: Authed,
    Extension(db): Extension<DB>,
    Path(username_to_delete): Path<String>,
) -> Result<String> {
    let mut tx = db.begin().await?;

    require_admin(&mut tx, &username).await?;

    let email_to_delete_o = sqlx::query_scalar!(
        "SELECT email FROM usr where username = $1",
        username_to_delete
    )
    .fetch_optional(&db)
    .await?;

    let email_to_delete =
        crate::utils::not_found_if_none(email_to_delete_o, "User", &username_to_delete)?;

    sqlx::query!("DELETE FROM password WHERE email = $1", email_to_delete)
        .execute(&mut tx)
        .await?;

    sqlx::query!(
        "DELETE FROM token WHERE owner = $1",
        owner_to_token_owner(&username_to_delete, false)
    )
    .execute(&mut tx)
    .await?;

    sqlx::query!("DELETE FROM usr WHERE email = $1", email_to_delete)
        .execute(&mut tx)
        .await?;

    audit_log(
        &mut tx,
        &username,
        "users.delete",
        ActionKind::Delete,
        Some(&username_to_delete),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("username {} deleted", username_to_delete))
}

async fn set_password(
    Extension(db): Extension<DB>,
    Extension(argon2): Extension<Arc<Argon2<'_>>>,
    Authed { username, .. }: Authed,
    Json(EditPassword { password }): Json<EditPassword>,
) -> Result<String> {
    let email = get_email_from_username(&username, &db).await?.unwrap();
    let mut tx = db.begin().await?;

    sqlx::query!(
        "UPDATE password SET password_hash = $1 WHERE email = $2",
        &hash_password(argon2, password)?,
        email,
    )
    .execute(&mut tx)
    .await?;

    audit_log(
        &mut tx,
        &username,
        "users.setpassword",
        ActionKind::Update,
        Some(&email),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!("password of {} updated", email))
}

pub async fn get_email_from_username(username: &String, db: &DB) -> Result<Option<String>> {
    let email = sqlx::query_scalar!("SELECT email FROM usr WHERE username = $1", username)
        .fetch_optional(db)
        .await?;
    Ok(email)
}

fn hash_password(argon2: Arc<Argon2>, password: String) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::InternalErr(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

async fn login(
    cookies: Cookies,
    Extension(db): Extension<DB>,
    Extension(argon2): Extension<Arc<Argon2<'_>>>,
    Json(Login {
        email_or_username,
        password,
    }): Json<Login>,
) -> Result<String> {
    let mut tx = db.begin().await?;

    let hash_o = sqlx::query_scalar!(
        "SELECT password_hash FROM password WHERE email = $1",
        email_or_username
    )
    .fetch_optional(&mut tx)
    .await?;

    let username_w_h: Option<(String, String)> = match hash_o {
        None => sqlx::query_as(
            "SELECT usr.username, password_hash FROM password LEFT JOIN usr ON password.email = \
                 usr.email WHERE usr.username = $1",
        )
        .bind(email_or_username)
        .fetch_optional(&mut tx)
        .await?,
        _ => hash_o.map(|h| (email_or_username, h)),
    };

    if let Some((username, hash)) = username_w_h {
        let parsed_hash =
            PasswordHash::new(&hash).map_err(|e| Error::InternalErr(e.to_string()))?;
        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            Err(Error::BadRequest("Invalid login".to_string()))
        } else {
            use rand::prelude::*;
            let token: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            sqlx::query!(
                "INSERT INTO token
            (token, owner, label, expiration)
            VALUES ($1, $2, $3, $4)",
                token,
                owner_to_token_owner(&username, false),
                "session",
                chrono::Utc::now() + chrono::Duration::hours(TTL_TOKEN_DB_H as i64)
            )
            .execute(&mut tx)
            .await?;

            sqlx::query!(
                "UPDATE usr
            SET last_accessed_at = $1
            where username = $2",
                chrono::Utc::now(),
                username
            )
            .execute(&mut tx)
            .await?;
            let mut cookie = Cookie::new(COOKIE_NAME, token.clone());
            cookie.set_path(COOKIE_PATH);
            cookies.add(cookie);
            audit_log(
                &mut tx,
                &username,
                "users.login",
                ActionKind::Create,
                Some(&truncate_token(&token)),
                None,
            )
            .await?;
            tx.commit().await?;
            Ok(token)
        }
    } else {
        Err(Error::BadRequest("Invalid login".to_string()))
    }
}

pub async fn create_token_for_owner(
    db: &DB,
    owner: &str,
    NewToken { label, expiration }: NewToken,
    username: &str,
) -> Result<String> {
    use rand::prelude::*;
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    let mut tx = db.begin().await?;

    sqlx::query!(
        "INSERT INTO token
            (token, owner, label, expiration)
            VALUES ($1, $2, $3, $4)",
        token,
        owner,
        label,
        expiration
    )
    .execute(&mut tx)
    .await?;
    audit_log(
        &mut tx,
        &username,
        "users.token.create",
        ActionKind::Create,
        Some(&truncate_token(&token)),
        Some(
            [
                label.as_ref().map(|label| ("label", &label[..])),
                expiration
                    .map(|x| x.to_string())
                    .as_ref()
                    .map(|exp| ("expiration", &exp[..])),
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(token)
}

async fn create_token(
    Extension(db): Extension<DB>,
    Authed { username, .. }: Authed,
    Json(new_token): Json<NewToken>,
) -> Result<(StatusCode, String)> {
    let token = create_token_for_owner(
        &db,
        &owner_to_token_owner(&username, false),
        new_token,
        &username,
    )
    .await?;
    Ok((StatusCode::CREATED, token))
}

async fn list_tokens(
    Extension(db): Extension<DB>,
    Authed { username, .. }: Authed,
) -> JsonResult<Vec<TruncatedToken>> {
    let rows = sqlx::query_as!(
        TruncatedToken,
        "SELECT label, concat(substring(token for 10)) as token_prefix, expiration FROM token \
         WHERE user = $1",
        username
    )
    .fetch_all(&db)
    .await?;
    Ok(Json(rows))
}

async fn delete_token(
    Extension(db): Extension<DB>,
    Authed { username, .. }: Authed,
    Path(token_prefix): Path<String>,
) -> Result<String> {
    let tokens_deleted: Vec<String> = sqlx::query_scalar(
        "DELETE FROM token WHERE owner = $1 AND
     token LIKE concat($2, '%') RETURNING concat(substring(token for 10), '*****')",
    )
    .bind(&owner_to_token_owner(&username, false))
    .bind(&token_prefix)
    .fetch_all(&db)
    .await?;

    let mut tx = db.begin().await?;
    audit_log(
        &mut tx,
        &username,
        "users.token.delete",
        ActionKind::Delete,
        Some(&token_prefix),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(format!(
        "deleted {} tokens {:?} with prefix {}",
        tokens_deleted.len(),
        tokens_deleted,
        token_prefix
    ))
}

pub async fn delete_expired_tokens_perdiodically(db: &DB) -> () {
    loop {
        let tokens_deleted_r: std::result::Result<Vec<String>, _> = sqlx::query_scalar(
            "DELETE FROM token WHERE expiration <= $1
        RETURNING concat(substring(token for 10), '*****')",
        )
        .bind(chrono::Utc::now())
        .fetch_all(db)
        .await;

        match tokens_deleted_r {
            Ok(tokens) => tracing::info!("deleted {} tokens: {:?}", tokens.len(), tokens),
            Err(e) => tracing::error!("Error deleting token: {}", e.to_string()),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

pub fn truncate_token(token: &str) -> String {
    let mut s = token[..10].to_owned();
    s.push_str("*****");
    s
}
