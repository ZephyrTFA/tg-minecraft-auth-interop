use std::error::Error;

use rocket::{main, routes};
mod tg_auth;

#[main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ensure oauth info
    tg_auth::get_oauth_info();

    rocket::build()
        .mount("/tg_auth", routes![tg_auth::index, tg_auth::login_finalize])
        .launch()
        .await?;
    Ok(())
}
