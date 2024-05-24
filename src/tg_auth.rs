use rocket::{
    get,
    http::Status,
    request::{FromRequest, Outcome},
    response::Redirect,
    Request,
};

pub struct TgOAuth {
    client_id: usize,
    client_secret: String,
    redirect_uri: String,
}

pub fn get_oauth_info() -> &'static TgOAuth {
    static mut OAUTH: Option<TgOAuth> = None;

    unsafe {
        if OAUTH.is_none() {
            if let Ok(client_id) = std::env::var("TG_OAUTH_CLIENT_ID") {
                // check env first
                let client_id = client_id.parse().unwrap();
                let client_secret = std::env::var("TG_OAUTH_CLIENT_SECRET").unwrap();
                let redirect_uri = std::env::var("TG_OAUTH_REDIRECT_URI").unwrap();
                OAUTH = Some(TgOAuth {
                    client_id,
                    client_secret,
                    redirect_uri,
                });
            } else if let Ok(oauth_file) = std::fs::read_to_string(".oauth") {
                // check for .oauth file
                let mut lines = oauth_file.lines();
                let client_id = lines.next().unwrap().parse().unwrap();
                let client_secret = lines.next().unwrap().to_string();
                let redirect_uri = lines.next().unwrap().to_string();
                OAUTH = Some(TgOAuth {
                    client_id,
                    client_secret,
                    redirect_uri,
                });
            } else {
                eprintln!("no oauth info found.");
                eprintln!("please create a .oauth file with the following format:");
                eprintln!("client_id");
                eprintln!("client_secret");
                eprintln!("redirect_uri");
                eprintln!("or set the TG_OAUTH_CLIENT_ID, TG_OAUTH_CLIENT_SECRET, and TG_OAUTH_REDIRECT_URI environment variables.");
                std::process::exit(1);
            }
        }
        OAUTH.as_ref().unwrap()
    }
}

#[get("/login")]
pub async fn index() -> Redirect {
    let oauth = get_oauth_info();

    Redirect::to(format!(
        "https://tgstation13.org/phpBB/app.php/tgapi/oauth/auth?client_id={}&redirect_uri={}&scope=user.groups",
        oauth.client_id, oauth.redirect_uri
    ))
}

pub struct OAuthCode {
    code: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OAuthCode {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let code = request.query_value("code");
        if code.is_none() {
            return Outcome::Error((Status::BadRequest, "missing auth code"));
        }
        let code: Result<String, _> = code.unwrap();
        if code.is_err() {
            return Outcome::Error((Status::BadRequest, "invalid auth code"));
        }

        Outcome::Success(OAuthCode {
            code: code.unwrap(),
        })
    }
}

fn map_reqwest_err(err: reqwest::Error) -> (Status, &'static str) {
    eprintln!("reqwest error: {:?}", err);
    (Status::InternalServerError, "reqwest error")
}

async fn get_oauth_token(code: &str) -> Result<String, (Status, &str)> {
    let oauth = get_oauth_info();

    let client = reqwest::Client::new();
    let res = client
        .post("https://tgstation13.org/phpBB/app.php/tgapi/oauth/token")
        .query(&[
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", oauth.redirect_uri.to_string()),
            ("client_id", oauth.client_id.to_string()),
            ("client_secret", oauth.client_secret.to_string()),
        ])
        .send()
        .await
        .map_err(map_reqwest_err)?;

    if !res.status().is_success() {
        eprintln!("error getting token: ({})", res.status(),);
        return Err((Status::InternalServerError, "error getting token"));
    }

    let body = res.text().await.map_err(map_reqwest_err)?;
    Ok(body)
}

#[get("/login/finalize")]
pub async fn login_finalize(code: OAuthCode) -> Status {
    let token = get_oauth_token(&code.code).await;
    if token.is_err() {
        eprintln!("error getting token: {:?}", token.err());
        return Status::InternalServerError;
    }

    let token = token.unwrap();
    println!("token: {}", token);

    Status::Ok
}
