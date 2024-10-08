use grammers_client::session::Session;
use grammers_client::{Client, Config, InitParams};
use grammers_tl_types as tl;
use log::info;
use std::env;
use tokio::runtime;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

const SESSION_FILE: &str = "reproduce.session";

async fn async_main() -> Result {
    let api_id = env!("TG_ID").parse().expect("TG_ID invalid");
    let api_hash = env!("TG_HASH").to_string();
    let token = env::args().nth(1).expect("token missing");

    info!("Connecting to Telegram...");
    let client = Client::connect(Config {
        session: Session::load_file_or_create(SESSION_FILE)?,
        api_id,
        api_hash: api_hash.clone(),
        params: InitParams {
            // Fetch the updates we missed while we were offline
            catch_up: true,
            ..Default::default()
        },
    })
    .await?;
    info!("Connected!");

    if !client.is_authorized().await? {
        info!("Signing in...");
        client.bot_sign_in(&token).await?;
        client.session().save_to_file(SESSION_FILE)?;
        info!("Signed in!");
    }

    info!("Making a call that returns...");
    let state = client.invoke(&tl::functions::updates::GetState {}).await?;
    info!("Got state: {:?}", state);

    info!("Making a call that never returns...");
    // I have patched the mtsender to call `self.try_reproduce_deadlock()` when it receives a
    // request of type `GetUsers`. This is not ideal but was the only way I could think of to
    // easily make something that reproduces the bug.
    // The deadlock is caused when the client tries to send a request when all of its salts are
    // expired or invalidated by the mtproto server. `try_reproduce_deadlock()` simulates this
    // situation by setting all salts to `0` before sending the request.
    let me = client
        .invoke(&tl::functions::users::GetUsers {
            id: vec![tl::enums::InputUser::UserSelf],
        })
        .await?;
    info!("Got me: {:?}", me);

    client.session().save_to_file(SESSION_FILE)?;
    Ok(())
}

fn main() -> Result {
    simple_logger::init_with_level(log::Level::Trace).expect("failed to initialize logger");
    runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
}
