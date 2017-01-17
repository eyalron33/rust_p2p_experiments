// to get bytes from PK in hex and to make PK from them
extern crate rustc_serialize;
use rustc_serialize::hex::FromHex;

extern crate tox;
use tox::toxcore::binary_io::*;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::*;
use tox::toxcore::network::*;

fn main() {
    // get PK bytes from some "random" bootstrap node (Impyy's)
    let bootstrap_pk_bytes = FromHex::from_hex("788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B").unwrap();
    // create PK from bytes
    let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

    // generate own PublicKey, SecretKey keypair
    let (pk, sk) = gen_keypair();

    // and to encrypt data there precomputed symmetric key is needed, created
    // from PK of the peer you want to send data to, and your own secret key.
    let precomp = precompute(&bootstrap_pk, &sk);

    // also generate nonce that will be needed to make the encryption happen
    let nonce = gen_nonce();

    // now create Ping request
    let ping = Ping::new()
                 .as_packet(); // and make Ping usable by DhtPacket

    // with Ping packet create DhtPacket, and serialize it to bytes
    let dhtpacket = DhtPacket::new(&precomp, &pk, &nonce, ping).to_bytes();

    // and since packet is ready, prepare the network part;
    // bind to given address and port in given range
    let socket = bind_udp("::".parse().unwrap(), 33445..33546)
        .expect("Failed to bind to socket!");

    // send DhtPacket via socket to the node (Imppy's)
    let sent_bytes = socket.send_to(&dhtpacket, &"178.62.250.138:33445".parse().unwrap())
        .expect("Failed to send bytes!").unwrap();

    println!("Sent {} bytes of Ping request to the bootstrap node", sent_bytes);
    // since data was sent, now receive response – for that, first prepare
    // buffer to receive data into
    let mut buf = [0; MAX_UDP_PACKET_SIZE];

    // and wait for the answer
    let (bytes, sender);
    loop {
        match socket.recv_from(&mut buf) {
            Ok(Some((b, s))) => {
                bytes = b;
                sender = s;
                break;
            },
            Ok(None) => continue,
            Err(e) => {
                panic!("Failed to receive data from socket: {}", e);
            }
        }
    }

    // try to de-serialize received bytes as `DhtPacket`
    let recv_packet = match DhtPacket::from_bytes(&buf[..bytes]) {
        Some(p) => p,
        // if parsing fails ↓
        None => {
            panic!("Received packet could not have been parsed!\n{:?}",
                       &buf[..bytes]);
        },
    };

    println!("Received packet from {}, with an encrypted payload:\n{:?}",
             sender, recv_packet);

    // decrypt payload of the received packet
    let payload = recv_packet.get_packet(&sk)
        .expect("Failed to decrypt payload!");
    println!("And contents of payload:\n{:?}", payload);
}