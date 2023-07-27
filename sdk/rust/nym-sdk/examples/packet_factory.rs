use nym_sdk::mixnet;
use nym_sphinx::forwarding::packet::MixPacket;

#[tokio::main]
async fn main() {
    nym_bin_common::logging::setup_logging();

    // that's Alice: creating the packets
    let mut alice = mixnet::MixnetClient::connect_new().await.unwrap();
    let alice_address = alice.nym_address().clone();
    println!("alice_address={alice_address}");

    // that's Bob: the eventual recipient of the message
    let mut bob = mixnet::MixnetClient::connect_new().await.unwrap();
    let bob_address = bob.nym_address();
    println!("bob_address={bob_address}");

    // Alice creates a packet to herself
    let packets = alice.create_mix_packet(
        [42u8; 4000],
        &bob_address,
    ).await.unwrap();
    println!("{:?}", packets);

    // serialize and deserialize
    let serialized_packets: Vec<Vec<u8>> = packets.into_iter().map(|x| x.into_bytes().unwrap()).collect();
    let packets = serialized_packets.into_iter().map(|x| MixPacket::try_from_bytes(x.as_slice()).unwrap()).collect();

    // that's Charlie: they send the packets
    let charlie = mixnet::MixnetClient::connect_new().await.unwrap();
    let charlie_address = charlie.nym_address();
    println!("charlie_address={charlie_address}");

    // let's do the actual sending
    charlie.send_packets(packets).await;

    // let's see that they receive our message
    bob
        .on_messages(|msg| println!("Received: {}", String::from_utf8_lossy(&msg.message)))
        .await;
}
