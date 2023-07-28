use std::ops::Deref;
use nym_sdk::mixnet;

#[tokio::main]
async fn main() {
    nym_bin_common::logging::setup_logging();

    let client = mixnet::MixnetClient::connect_new().await.unwrap();

    let our_address = client.nym_address();
    println!("Our client nym address is: {our_address}");

    let secrets = client.get_secrets();
    println!("Our identity keypair: {:?}", secrets.identity_keypair.deref());
}
