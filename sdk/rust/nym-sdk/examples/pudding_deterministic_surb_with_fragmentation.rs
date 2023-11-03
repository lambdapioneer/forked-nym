use nym_sdk::mixnet;
use nym_sphinx::anonymous_replies::ReplySurb;

#[tokio::main]
async fn main() {
    nym_bin_common::logging::setup_logging();

    // that's Alice: creating the SURBs
    let alice = mixnet::MixnetClient::connect_new().await.unwrap();
    let alice_address = alice.nym_address();
    println!("alice_address={alice_address}");

    // that's Bob: the eventual recipient of the message
    let mut bob = mixnet::MixnetClient::connect_new().await.unwrap();
    let bob_address = bob.nym_address();
    println!("bob_address={bob_address}");

    let many_surbs = alice.create_surbs(bob_address, b"nonce".to_vec(), 10).await.unwrap();
    let many_serialized_surbs: Vec<String> = many_surbs.into_iter().map(|x| x.to_base58_string()).collect();
    assert_eq!(many_serialized_surbs.len(), 10);

    // that's Charlie: they use our SURBs to send a message
    let charlie = mixnet::MixnetClient::connect_new().await.unwrap();
    let charlie_address = charlie.nym_address();
    println!("charlie_address={charlie_address}");

    // the message is much larger than what would fit in the payload of a single message
    let many_surbs: Vec<ReplySurb> = many_serialized_surbs.into_iter().map(|x| ReplySurb::from_base58_string(x).unwrap()).collect();
    let very_long_message = [42u8; 4000];
    charlie.send_bytes_with_surbs(many_surbs, very_long_message).await;

    // and back to Bob: let's see that they receive our message
    bob
        .on_messages(|msg| println!("Received a message with {} bytes", &msg.message.len()))
        .await;
}
