use once_cell::sync::Lazy;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tera::{Context, Tera};
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{
    reject::{Reject, Rejection},
    Filter, Reply,
};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    let mut tera = match Tera::new("templates/*") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };
    tera.autoescape_on(vec!["html", ".sql"]);
    tera
});

#[tokio::main]
async fn main() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    // GET /css/
    let css = warp::path!("css")
        .and(warp::fs::file("css/compiled.css"))
        .with(warp::trace::named("css"));

    // GET /
    let issues = warp::path::end()
        .and(warp::get())
        .and_then(issues_handler)
        .with(warp::trace::named("dashboard"));

    let routes = issues.or(css).with(warp::trace::request());
    warp::serve(routes)
        .tls()
        .cert_path("certs/localhost.crt")
        .key_path("certs/localhost.key")
        .run(([127, 0, 0, 1], 3030))
        .await;
}

async fn issues_handler() -> Result<impl Reply, Rejection> {
    let gh = {
        let user = base64::encode(
            String::from("mgattozzi:")
                + &std::env::var("GITHUB").map_err(|_| InternalServerErrors::EnvVar)?,
        );
        format!("Basic {}", user)
    };
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&gh).map_err(|_| InternalServerErrors::InvalidHeader)?,
    );
    headers.insert(
        header::ACCEPT,
        header::HeaderValue::from_static("Accept: application/vnd.github.v3+json"),
    );
    let client = Client::builder()
        .user_agent(APP_USER_AGENT)
        .default_headers(headers)
        .build()
        .map_err(|_| InternalServerErrors::ClientBuildFail)?;
    let issues = client
        .execute(
            client
                .get("https://api.github.com/issues")
                .build()
                .map_err(|_| InternalServerErrors::RequestBuildFail)?,
        )
        .await
        .map_err(|e| InternalServerErrors::BadGitHubRequest(e))?
        .json::<Vec<GhIssue>>()
        .await
        .map_err(|e| InternalServerErrors::ConvertToJSON(e))?;
    let notifications = client
        .execute(
            client
                .get("https://api.github.com/notifications")
                .build()
                .map_err(|_| InternalServerErrors::RequestBuildFail)?,
        )
        .await
        .map_err(|e| InternalServerErrors::BadGitHubRequest(e))?
        .json::<Vec<GhNotification>>()
        .await
        .map_err(|e| InternalServerErrors::ConvertToJSON(e))?
        .into_iter()
        .filter(|ghn| ghn.unread == true)
        .collect::<Vec<GhNotification>>();
    let mut ctx = Context::new();
    ctx.insert("issues", &issues);
    ctx.insert("notifications", &notifications);
    let render = TEMPLATES
        .render("issues.html", &ctx)
        .map_err(|e| InternalServerErrors::RenderIssue(e))?;
    Ok(warp::reply::html(render))
}

#[derive(Debug)]
enum ServerError {
    Security(SecurityError),
    Internal(InternalServerErrors),
}
impl Reject for ServerError {}

#[derive(Debug)]
enum SecurityError {
    DirectoryTraversal,
}
impl Reject for SecurityError {}

#[derive(Debug)]
enum InternalServerErrors {
    BadGitHubRequest(reqwest::Error),
    ConvertToJSON(reqwest::Error),
    EnvVar,
    ClientBuildFail,
    RequestBuildFail,
    InvalidHeader,
    RenderIssue(tera::Error),
    IO(std::io::Error),
    Conversion(std::string::FromUtf8Error),
}

impl Reject for InternalServerErrors {}

#[derive(Serialize, Deserialize, Debug)]
struct GhNotification {
    reason: Reason,
    unread: bool,
    repository: GhRepo,
    subject: Subject,
}
#[derive(Serialize, Deserialize, Debug)]
struct Subject {
    title: String,
    url: url_serde::SerdeUrl,
}

#[derive(Serialize, Deserialize, Debug)]
enum Reason {
    #[serde(rename(deserialize = "assign"))]
    Assign,
    #[serde(rename(deserialize = "author"))]
    Author,
    #[serde(rename(deserialize = "comment"))]
    Comment,
    #[serde(rename(deserialize = "invitation"))]
    Invitation,
    #[serde(rename(deserialize = "manual"))]
    Manual,
    #[serde(rename(deserialize = "mention"))]
    Mention,
    #[serde(rename(deserialize = "review_requested", serialize = "Review Requested"))]
    ReviewRequested,
    #[serde(rename(deserialize = "security_alert", serialize = "Security Alert"))]
    SecurityAlert,
    #[serde(rename(deserialize = "state_change", serialize = "State Change"))]
    StateChange,
    #[serde(rename(deserialize = "subscribed"))]
    Subscribed,
    #[serde(rename(deserialize = "team_mention", serialize = "Team Mention"))]
    TeamMention,
}

#[derive(Serialize, Deserialize, Debug)]
struct GhIssue {
    repository: GhRepo,
    number: usize,
    state: State,
}

#[derive(Serialize, Deserialize, Debug)]
struct GhRepo {
    full_name: String,
    html_url: url_serde::SerdeUrl,
}

#[derive(Serialize, Deserialize, Debug)]
enum State {
    #[serde(rename(deserialize = "open"))]
    Open,
    #[serde(rename(deserialize = "closed"))]
    Closed,
}
