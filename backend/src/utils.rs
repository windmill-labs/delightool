/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use sqlx::{Postgres, Transaction};

use crate::error::{Error, Result};

pub const MAX_PER_PAGE: usize = 100;
pub const DEFAULT_PER_PAGE: usize = 30;

#[derive(Deserialize)]
pub struct Pagination {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}
#[derive(Deserialize)]
pub struct StripPath(String);

impl StripPath {
    pub fn to_path(&self) -> &str {
        self.0.strip_prefix('/').unwrap()
    }
}

pub async fn require_admin<'c>(db: &mut Transaction<'c, Postgres>, username: &str) -> Result<()> {
    let is_admin = sqlx::query_scalar!("SELECT is_admin FROM usr where username = $1", username)
        .fetch_one(db)
        .await?;
    if !is_admin {
        Err(Error::NotAuthorized(
            "This endpoint require caller to be an admin".to_owned(),
        ))
    } else {
        Ok(())
    }
}

pub fn rd_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn paginate(pagination: Pagination) -> (usize, usize) {
    let per_page = pagination
        .per_page
        .unwrap_or(DEFAULT_PER_PAGE)
        .max(1)
        .min(MAX_PER_PAGE);
    let offset = (pagination.page.unwrap_or(1).max(1) - 1) * per_page;
    (per_page, offset)
}

pub fn not_found_if_none<T, U: AsRef<str>>(opt: Option<T>, kind: &str, name: U) -> Result<T> {
    if let Some(o) = opt {
        Ok(o)
    } else {
        Err(Error::NotFound(format!(
            "{} not found at name {}",
            kind,
            name.as_ref()
        )))
    }
}

pub fn get_owner_from_path(path: &str) -> String {
    path.split('/').take(2).collect::<Vec<_>>().join("/")
}
