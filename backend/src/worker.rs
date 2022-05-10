/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use magic_crypt::MagicCrypt256;
use std::{
    process::{ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    db::DB,
    error::Error,
    jobs::{add_completed_job, delete_job, pull, push, JobKind, JobPayload, QueuedJob},
    pipenv::{self, pipenv_by_id, DEFAULT_PY_V, PIPFILE_PRELUDE},
    schedule::get_schedule_opt,
    users::{create_token_for_owner, get_email_from_username},
    variables,
};

use futures::{stream, StreamExt};

use serde_json::{Map, Value};

use tokio::{
    fs::{DirBuilder, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::Mutex,
    time::Instant,
};


use tokio::sync::mpsc;

const CONCURRENCY: usize = 5;
const TMP_DIR: &str = "/tmp/delightool";
const NUM_SECS_ENV_CHECK: u64 = 15;
const SLEEP_QUEUE: u64 = 50;


pub async fn get_last_env_id(db: &DB) -> i32 {
    crate::pipenv::pipenv_last_id_valid(&db.clone())
        .await
        .expect("impossible to retrieve pipenv lastid")
        .unwrap_or(-1)
}

pub async fn run_worker(
    db: &DB,
    mc: Arc<MagicCrypt256>,
    timeout: i32,
    worker_instance: &str,
    worker_name: String,
    i_worker: u64,
    num_workers: u64,
    mutex: Arc<Mutex<i32>>,
    ip: &str
) {

    let worker_dir = format!("{}/{}", TMP_DIR, worker_name);
    tracing::info!(worker_dir = %worker_dir, worker_name = %worker_name, "Creating worker dir");
    DirBuilder::new()
        .recursive(true)
        .create(&worker_dir)
        .await
        .expect("could not create initial worker dir");

    let mut last_env_id: i32 = -1;
    let mut last_env_check = Instant::now() - Duration::from_secs(NUM_SECS_ENV_CHECK + 1);

    insert_initial_ping(worker_instance, &worker_name, ip, db).await;

    if i_worker == 1 {
        tracing::info!(worker_name = %worker_name, "Master worker pipenv setup job start");

        let last_env = crate::pipenv::last_pipenv(db)
            .await
            .expect("could not get last pipenv")
            .map(|p| crate::pipenv::AddPipenv {
                python_version: p.python_version,
                dependencies: p.dependencies,
            })
            .unwrap_or(crate::pipenv::AddPipenv {
                python_version: Some(DEFAULT_PY_V.to_string()),
                dependencies: vec![],
            });
        let env_id = crate::pipenv::insert_pipenv(&db.clone(), "system".to_string(), last_env)
            .await
            .expect("could not insert initial pipenv");
        let tx = db.begin().await.expect("Impossible to acquire pool");
        let (job_id, tx) = push(
            tx,
            &JobPayload::Dependencies(env_id),
            None,
            "system",
            "g/all".to_string(),
            None,
            None,
            None,
        )
        .await
        .expect("Impossible to push initial dependency job");
        tx.commit().await.expect("Impossible to commit");

        tracing::info!(worker_name = %worker_name, job_id = %job_id, "Pushed env initialization job");

        let pulled_job = pull(db, 1, Some(job_id.to_string()), None)
            .await
            .expect("impossible to pull pipenvs")
            .into_iter()
            .next()
            .expect("impossible to retrieve last pushed pipenv");

        tracing::info!(worker_name = %worker_name, job_id = %pulled_job.id, "Pulled env initialization job");
        let _ = mutex.lock().await;
        if let Some(err) = handle_queued_job(
            pulled_job,
            db,
            mc.clone(),
            timeout,
            &worker_name,
            &worker_dir,
            last_env_id,
        )
        .await
        .err()
        {
            tracing::error!(job_id = %job_id, "Error handling job {}", err.to_string())
        };
    }

    loop {
        tracing::info!(worker_name = %worker_name, worker_env_id = %last_env_id, "waiting for last_env_id to be > 0");
        if get_last_env_id(db).await < 0 {
            tokio::time::sleep(Duration::from_secs(num_workers)).await;
        } else {
            break;
        }
    }

    // leave every worker some time to do install with full memory
    tokio::time::sleep(Duration::from_secs(15 * (i_worker - 1))).await;

    let mut jobs_executed = 0;
    loop {
        if last_env_check.elapsed().as_secs() > NUM_SECS_ENV_CHECK {
            let nlast_id = get_last_env_id(db).await;
            tracing::debug!(
                worker_name = %worker_name,
                 worker_env_id = %last_env_id,
                 last_valid_id= %nlast_id,
                "checking last valid env id vs worker env id");
            if nlast_id > last_env_id {
                tracing::info!(worker_name = %worker_name, env_to_install = %nlast_id, "attempting to install latest env");
                sync_worker(&db.clone(), &worker_dir, nlast_id, mutex.clone())
                    .await
                    .expect("could not sync worker");
                tracing::info!(worker_name = %worker_name, env_to_install = %nlast_id, "latest env installed");

                last_env_id = nlast_id;
            }
            sqlx::query!("UPDATE worker_ping SET ping_at = $1, env_id = $2, jobs_executed = $3 WHERE worker = $4", 
                chrono::Utc::now(),
                last_env_id, 
                jobs_executed,
                &worker_name)
                .execute(db)
                .await
                .expect("update worker ping");

            last_env_check = Instant::now();
        }

        let jobs = match pull(db, CONCURRENCY as u32, None, Some(last_env_id)).await {
            Ok(jobs) => jobs,
            Err(err) => {
                tracing::error!(worker = %worker_name, "run_worker: pulling jobs: {}", err);
                tokio::time::sleep(Duration::from_millis(500)).await;
                Vec::new()
            }
        };

        let number_of_jobs = jobs.len();
        jobs_executed += number_of_jobs as i32;
        
        if number_of_jobs > 0 {
            tracing::info!(worker = %worker_name, number_of_jobs = number_of_jobs, "Fetched jobs");
            stream::iter(jobs)
                .for_each_concurrent(CONCURRENCY, |job| async {
                    let job_id = job.id;
                    if let Some(err) = handle_queued_job(
                        job,
                        db,
                        mc.clone(),
                        timeout,
                        &worker_name,
                        &worker_dir,
                        last_env_id,
                    )
                    .await
                    .err()
                    {
                        tracing::error!(job_id = %job_id, "Error handling job {}", err.to_string())
                    };
                })
                .await;
        }

        // sleep not to overload our database
        tokio::time::sleep(Duration::from_millis(SLEEP_QUEUE * num_workers)).await;
    }
}

async fn insert_initial_ping(worker_instance: &str, worker_name: &str, ip: &str, db: &DB) {
    sqlx::query!("INSERT INTO worker_ping (worker_instance, worker, ip) VALUES ($1, $2, $3)", worker_instance, worker_name, ip)
        .execute(db)
        .await
        .expect("insert worker_ping initial value");
}

async fn sync_worker(
    db: &DB,
    worker_dir: &str,
    id: i32,
    mutex: Arc<Mutex<i32>>,
) -> crate::error::Result<()> {
    let env = pipenv_by_id(db, id)
        .await?
        .expect("cannot fetch pipenv to sync worker");
    write_pipfile(worker_dir, &env).await?;
    let path_lock = format!("{}/Pipfile.lock", worker_dir);
    let mut pipfile_lock = File::create(path_lock.clone()).await?;
    pipfile_lock
        .write_all(
            env.pipfile_lock
                .expect("unexpected empty pipfile lock")
                .as_bytes(),
        )
        .await
        .expect("could not write pipfile lock");
    pipfile_lock.sync_all().await?;
    loop {
        let _ = mutex.lock().await;
        let pipenv_sync = Command::new("pipenv")
            .current_dir(worker_dir)
            .env("PIP_NO_CACHE_DIR", "false")
            .args(vec!["sync"])
            .output()
            .await?;
        tracing::info!(
        stdout = %String::from_utf8(pipenv_sync.stdout.clone()).unwrap(),
         stderr = %String::from_utf8(pipenv_sync.stderr.clone()).unwrap(), 
         status = ?pipenv_sync.status,
          dir = %worker_dir, "pipenv sync");

        if pipenv_sync.status.success() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

async fn handle_queued_job(
    job: QueuedJob,
    db: &sqlx::Pool<sqlx::Postgres>,
    mc: Arc<MagicCrypt256>,
    timeout: i32,
    worker_name: &str,
    worker_dir: &str,
    env_id: i32,
) -> crate::error::Result<()> {
    let job_id = job.id;
    let schedule_path = job.schedule_path.clone();
    let script_hash = job.script_hash;
    let script_path = job.script_path.clone();

    let mut logs = "".to_string();
    let mut last_line = "{}".to_string();

    let execution = handle_job(
        &job,
        db,
        &mc,
        timeout,
        worker_name,
        worker_dir,
        &mut logs,
        &mut last_line,
        env_id,
    )
    .await;
    let duration =
        (chrono::Utc::now() - job.started_at.unwrap_or(job.created_at)).num_seconds() as i32;
    let cj = match execution {
        Ok(r) => add_completed_job(db, job, duration, true, r.result, logs),
        Err(e) => {
            let mut output_map = serde_json::Map::new();
            output_map.insert(
                "error".to_string(),
                serde_json::Value::String(e.to_string()),
            );
            add_completed_job(
                db,
                job,
                duration,
                false,
                Some(output_map),
                format!("{}\n-- END OF LOGS --\n\nerror:\n{}", logs, e.to_string()),
            )
        }
    }
    .await;
    let _ = delete_job(db, job_id)
        .await
        .and(cj)
        .map_err(|e| tracing::error!(worker = %worker_name, job_id = %job_id, "Error deleting the job: {}", e));
    if let Some(schedule_path) = schedule_path {
        let mut tx = db.begin().await?;
        let schedule = get_schedule_opt(&mut tx, &schedule_path).await?.unwrap();
        if schedule.enabled {
            tx = crate::schedule::push_scheduled_job(
                tx,
                schedule,
                (script_hash.unwrap(), script_path.unwrap()),
            )
            .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

struct JobResult {
    result: Option<Map<String, Value>>,
}

#[allow(clippy::too_many_arguments)]
async fn handle_job(
    job: &QueuedJob,
    db: &DB,
    mc: &Arc<MagicCrypt256>,
    timeout: i32,
    worker_name: &str,
    worker_dir: &str,
    mut logs: &mut String,
    mut last_line: &mut String,
    env_id: i32,
) -> Result<JobResult, Error> {
    tracing::info!(
        worker = %worker_name,
        job_id = %job.id,
        "handling job"
    );

    logs.push_str(&format!(
        "job {} on worker {} with env id {:?}\n",
        &job.id, &worker_name, &env_id
    ));

    let status: crate::error::Result<ExitStatus>;
    if matches!(job.job_kind, JobKind::Dependencies) {
        let env_id = job.env_id.expect("env id not set for dep job");
        pipenv::set_job_id(db, job.id, env_id).await?;
        let pipenv = pipenv::pipenv_by_id(db, env_id)
            .await?
            .expect("pipenv not found");
        logs.push_str(&format!("pipenv: {:?}\n", &pipenv));
        let content = write_pipfile(worker_dir, &pipenv).await?;
        logs.push_str(&format!("content of pipfile:\n{}\n", &content));

        let child = Command::new("pipenv")
            .current_dir(&worker_dir)
            .env("PIP_NO_CACHE_DIR", "false")
            .args(vec!["install", "--verbose"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        status = handle_child(job, db, &mut logs, &mut last_line, timeout, child).await;

        if status.as_ref().unwrap().success() {
            *last_line = r#"{ "success": "Successful pipenv install" }"#.to_string();

            let path_lock = format!("{}/Pipfile.lock", worker_dir);
            let mut file = File::open(path_lock).await?;

            let mut content = "".to_string();
            file.read_to_string(&mut content).await?;
            pipenv::set_pipenv_lock(db, content, job.env_id.unwrap()).await?;
        }
    } else {
        let python_filename = format!("{}.py", job.id);
        let path = format!("{}/{}", worker_dir, python_filename);
        let mut wrapper_file = File::create(path.clone()).await?;
        let wrapper_content: String = format!(
            r#"
import json
inner_script = __import__("{}_inner")

kwargs = json.loads("""{}""", strict=False)

res = inner_script.main(**kwargs)
if res is None:
    res = {{}}
if isinstance(res, list):
    res = {{f"res{{i+1}}": v for i, v in enumerate(res)}}
if not isinstance(res, dict):
    res = {{ "res1": res }}
res_json = json.dumps(res, separators=(',', ':'), default=str).replace('\n', '')
print()
print("result:")
print(res_json)
"#,
            job.id,
            serde_json::to_string(&job.args).map_err(|e| { Error::ExecutionErr(e.to_string()) })?.replace("\\\"", "\\\\\"")
        );
        wrapper_file.write_all(wrapper_content.as_bytes()).await?;
        wrapper_file.sync_all().await?;
        let inner_path = format!("{}/{}_inner.py", worker_dir, job.id);
        let mut inner_file = File::create(&inner_path).await?;

        let inner_content: String = if matches!(job.job_kind, JobKind::Preview) {
            (job.raw_code.as_ref().unwrap_or(&"no raw code".to_owned())).to_owned()
        } else {
            sqlx::query_scalar("SELECT content FROM script WHERE hash = $1")
                .bind(&job.script_hash)
                .fetch_optional(db)
                .await?
                .unwrap_or_else(|| "no code at hash".to_owned())
        };
        inner_file.write_all(inner_content.as_bytes()).await?;
        inner_file.sync_all().await?;
        let mut tx = db.begin().await?;

        let variables = variables::get_all_variables(&mut tx, mc)
            .await?
            .into_iter()
            .map(|s| (s.name, s.value));

        let token = create_token_for_owner(
            &db,
            &job.permissioned_as,
            crate::users::NewToken {
                label: Some("ephemeral-script".to_string()),
                expiration: Some(
                    chrono::Utc::now() + chrono::Duration::seconds((timeout * 2).into()),
                ),
            },
            &job.created_by,
        )
        .await?;
        tx.commit().await?;
        let reserved_variables = variables::get_reserved_variables(
            &token,
            &get_email_from_username(&job.created_by, db)
                .await?
                .unwrap_or_else(|| "nosuitable@email.xyz".to_string()),
            &job.created_by,
            &job.id.to_string(),
        )
        .into_iter()
        .map(|rv| (rv.name, rv.value));

        let child = Command::new("pipenv")
            .current_dir(worker_dir)
            .envs(variables)
            .envs(reserved_variables)
            .args(vec!["run", "python3", "-u", "-B", &python_filename])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        status = handle_child(job, db, &mut logs, &mut last_line, timeout, child).await;

        tokio::fs::remove_file(path).await?;
        tokio::fs::remove_file(inner_path).await?;
    }

    if status.is_ok() && status.as_ref().unwrap().success() {
        let result = serde_json::from_str::<Map<String, Value>>(last_line).map_err(|e| {
            Error::ExecutionErr(format!(
                "result {} is not parsable.\n err: {}",
                last_line,
                e.to_string()
            ))
        })?;
        Ok(JobResult {
            result: Some(result),
        })
    } else {
        let err = if status.is_ok() {
            format!("Status: {}", status.unwrap())
        } else {
            format!("error before termination: {}", status.err().unwrap())
        };
        Err(Error::ExecutionErr(err))
    }
}

async fn write_pipfile(worker_dir: &str, pipenv: &pipenv::Pipenv) -> crate::error::Result<String> {
    let path = format!("{}/Pipfile", worker_dir);
    let mut pipfile = File::create(path).await?;
    let pipfile_content = format!(
        r#"
{}
{}

[dev-packages]

[requires]
python_version = "{}"
"#,
        PIPFILE_PRELUDE,
        pipenv.dependencies.join("\n"),
        pipenv
            .python_version
            .as_ref()
            .unwrap_or(&DEFAULT_PY_V.to_string())
    );
    pipfile.write_all(pipfile_content.as_bytes()).await?;
    pipfile.sync_all().await?;
    Ok(pipfile_content)
}

async fn handle_child(
    job: &QueuedJob,
    db: &DB,
    logs: &mut String,
    last_line: &mut String,
    timeout: i32,
    mut child: Child,
) -> crate::error::Result<ExitStatus> {
    let stderr = child
        .stderr
        .take()
        .expect("child did not have a handle to stdout");

    let stdout = child
        .stdout
        .take()
        .expect("child did not have a handle to stdout");

    let mut reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    let done = Arc::new(AtomicBool::new(false));

    let done1 = done.clone();
    // Ensure the child process is spawned in the runtime so it can
    // make progress on its own while we await for any output.
    let handle = tokio::spawn(async move {
        let inner_done = done1.clone();
        let r: Result<ExitStatus, anyhow::Error> = tokio::select! {
            r = child.wait() => {
                inner_done.store(true, Ordering::Relaxed);
                Ok(r?)
            }
            _ = async move {
                loop {
                    if done1.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            } => {
                child.kill().await?;
                return Err(Error::ExecutionErr("execution interrupted (likely timeout or cancel)".to_string()).into())
            }
        };
        r
    });

    let (tx, mut rx) = mpsc::channel::<String>(100);
    let id = job.id;

    tokio::spawn(async move {
        loop {
            let send = tokio::select! {
                Ok(Some(out)) = reader.next_line() => tx.send(out).await,
                Ok(Some(err)) = stderr_reader.next_line() => tx.send(err).await,
                else => {
                    break
                },
            };
            if send.err().is_some() {
                tracing::error!("error sending log line");
            };
        }
    });

    let db2 = db.clone();
    let done3 = done.clone();

    tokio::spawn(async move {
        while !&done3.load(Ordering::Relaxed) {
            let q = sqlx::query!(
                "UPDATE queue SET last_ping = $1 WHERE id = $2",
                chrono::Utc::now(),
                id
            )
            .execute(&db2)
            .await;

            if q.is_err() {
                tracing::error!("error setting last ping for id {}", id);
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let mut last_update_done = Instant::now();

    let mut start = 0;
    while let Some(nl) = rx.recv().await {
        logs.push('\n');
        logs.push_str(&nl);
        *last_line = nl.clone();
        let end = logs.len();

        if last_update_done.elapsed().as_millis() > 500 {
            if start != end {
                send_logs(&logs[start..end], id, db).await;
                start = end;
            }

            let canceled = sqlx::query_scalar!("SELECT canceled FROM queue WHERE id = $1", id)
                .fetch_one(db)
                .await
                .map_err(|_| tracing::error!("error getting canceled for id {}", id));

            if canceled.unwrap_or(false) {
                tracing::info!("killed after cancel: {}", job.id);
                done.store(true, Ordering::Relaxed);
            }

            let has_timeout = job
                .started_at
                .map(|sa| (chrono::Utc::now() - sa).num_seconds() > timeout as i64)
                .unwrap_or(false);

            if has_timeout {
                let q = sqlx::query(&format!(
                    "UPDATE queue SET canceled = true, canceled_by = 'timeout', \
                         canceled_reason = 'duration > {}' WHERE id = $1",
                    timeout
                ))
                .bind(id)
                .execute(db)
                .await;

                if q.is_err() {
                    tracing::error!("error setting canceled for id {}", id);
                }
            }
            last_update_done = Instant::now();
        }
    }

    let status = handle
        .await
        .map_err(|e| Error::ExecutionErr(e.to_string()))??;
    Ok(status)
}

async fn send_logs(logs: &str, id: uuid::Uuid, db: &DB) {
    if sqlx::query!(
        "UPDATE queue SET logs = concat(logs, $1::text) WHERE id = $2",
        logs.to_owned(),
        id
    )
    .execute(db)
    .await
    .is_err()
    {
        tracing::error!("error updating logs for id {}", id)
    };
}

pub async fn restart_zombie_jobs(db: &DB, timeout: i32) {
    sqlx::query!(
        "UPDATE queue SET running = false WHERE last_ping < $1",
        chrono::Utc::now() - chrono::Duration::seconds(timeout as i64 * 2)
    )
    .execute(db)
    .await
    .ok();
}
