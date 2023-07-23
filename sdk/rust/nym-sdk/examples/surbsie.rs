use nym_sdk::mixnet;
use nym_sphinx::anonymous_replies::ReplySurb;

#[tokio::main]
async fn main() {
    nym_bin_common::logging::setup_logging();

    // that's Alice: creating the SURBs
    let mut alice = mixnet::MixnetClient::connect_new().await.unwrap();
    let alice_address = alice.nym_address();
    println!("alice_address={alice_address}");

    // that's Bob: the eventual recipient of the message
    let mut bob = mixnet::MixnetClient::connect_new().await.unwrap();
    let bob_address = bob.nym_address();
    println!("bob_address={bob_address}");

    // both SURBs should be identical given the same nonce
    let surb_serialized_1 = alice.create_surb(bob_address, b"nonce".to_vec()).await.unwrap().to_base58_string();
    let surb_serialized_2 = alice.create_surb(bob_address, b"nonce".to_vec()).await.unwrap().to_base58_string();
    assert_eq!(surb_serialized_1, surb_serialized_2);

    // that's Charlie: they use our SURB to send a message
    let mut charlie = mixnet::MixnetClient::connect_new().await.unwrap();
    let charlie_address = charlie.nym_address();
    println!("charlie_address={charlie_address}");

    let surb = ReplySurb::from_base58_string(surb_serialized_1).unwrap();
    charlie.send_bytes_with_surb(surb, "Hello world!").await;

    // and back to Bob: let's see that they receive our message
    bob
        .on_messages(|msg| println!("Received: {}", String::from_utf8_lossy(&msg.message)))
        .await;
}
