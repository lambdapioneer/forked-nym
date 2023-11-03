// Copyright 2021-2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::encryption_key::{SurbEncryptionKey, SurbEncryptionKeyError, SurbEncryptionKeySize};
use nym_crypto::generic_array::typenum::Unsigned;
use nym_crypto::generic_array::GenericArray;
use nym_sphinx_addressing::clients::{ClientEncryptionKey, Recipient};
use nym_sphinx_addressing::nodes::{NymNodeRoutingAddress, MAX_NODE_ADDRESS_UNPADDED_LEN};
use nym_sphinx_params::packet_sizes::PacketSize;
use nym_sphinx_params::{
    PacketType, DEFAULT_NUM_MIX_HOPS, SURB_MAX_VARIANT_OVERHEAD, SURB_PUDDING_VARIANT_OVERHEAD,
};
use nym_sphinx_types::{NymPacket, SURBMaterial, SphinxError, SURB};
use nym_topology::{NymTopology, NymTopologyError};
use rand::{CryptoRng, RngCore};
use serde::de::{Error as SerdeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::{self, Formatter};
use std::time;
use thiserror::Error;

use nym_crypto::aes;
use nym_crypto::asymmetric::encryption::KeyPair;
use nym_crypto::ctr;
use nym_crypto::shared_key::new_ephemeral_shared_key;
use nym_crypto::symmetric::stream_cipher;
use nym_crypto::symmetric::stream_cipher::CipherKey;
use rand::rngs::OsRng;
type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

#[derive(Debug, Error)]
pub enum ReplySurbError {
    #[error("tried to use reply SURB with an unpadded message")]
    UnpaddedMessageError,

    #[error("reply SURB is incorrectly formatted: {0}")]
    MalformedStringError(#[from] bs58::decode::Error),

    #[error("failed to recover reply SURB from bytes: {0}")]
    RecoveryError(#[from] SphinxError),

    #[error("failed to recover reply SURB encryption key from bytes: {0}")]
    InvalidEncryptionKeyData(#[from] SurbEncryptionKeyError),
}

#[derive(Debug)]
pub struct ReplySurb {
    pub(crate) surb: SURB,
    pub(crate) encryption_key: SurbEncryptionKey,

    // our variant header consists of
    // - the public part of the ephemeral key pair: 32 Bytes [^1]
    // - the encrypted surb encryption key: 16 Bytes
    // - the encrypted 0x00...0x00 decryption check : 8 Bytes
    pub external_variant_data: Vec<u8>,
}

// Serialize + Deserialize is not really used anymore (it was for a CBOR experiment)
// however, if we decided we needed it again, it's already here
impl Serialize for ReplySurb {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for ReplySurb {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReplySurbVisitor;

        impl<'de> Visitor<'de> for ReplySurbVisitor {
            type Value = ReplySurb;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "A replySURB must contain a valid symmetric encryption key and a correctly formed sphinx header")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                ReplySurb::from_bytes(bytes)
                    .map_err(|_| SerdeError::invalid_length(bytes.len(), &self))
            }
        }

        deserializer.deserialize_bytes(ReplySurbVisitor)
    }
}

impl ReplySurb {
    pub fn max_msg_len(packet_size: PacketSize) -> usize {
        // For detailed explanation (of ack overhead) refer to common\nymsphinx\src\preparer.rs::available_plaintext_per_packet()
        let ack_overhead = MAX_NODE_ADDRESS_UNPADDED_LEN + PacketSize::AckPacket.size();
        packet_size.plaintext_size() - ack_overhead - SURB_MAX_VARIANT_OVERHEAD - 1
    }

    pub fn construct<R>(
        rng: &mut R,
        recipient: &Recipient,
        average_delay: time::Duration,
        topology: &NymTopology,
    ) -> Result<Self, NymTopologyError>
    where
        R: RngCore + CryptoRng,
    {
        let route =
            topology.random_route_to_gateway(rng, DEFAULT_NUM_MIX_HOPS, recipient.gateway())?;
        let delays = nym_sphinx_routing::generate_from_average_duration_with_rng(
            average_delay,
            route.len(),
            rng,
        );
        let destination = recipient.as_sphinx_destination();

        let surb_material = SURBMaterial::new(route, delays, destination);
        let surb = surb_material.construct_SURB_with_rng(rng).unwrap();

        let encryption_key = SurbEncryptionKey::new(rng);
        let external_variant_data = Self::build_external_variant_data(&recipient, &encryption_key);

        // this can't fail as we know we have a valid route to gateway and have correct number of delays
        Ok(ReplySurb {
            surb,
            encryption_key,
            external_variant_data,
        })
    }

    fn build_external_variant_data(
        recipient: &Recipient,
        surb_encryption_key: &SurbEncryptionKey,
    ) -> Vec<u8> {
        // derive an ephemeral secret using an ephemeral key pair and the recipient public key
        let ephemeral_key_pair = KeyPair::new(&mut OsRng);
        let recipient_public_key: &ClientEncryptionKey = recipient.encryption_key();
        let ephemeral_secret = ephemeral_key_pair
            .private_key()
            .diffie_hellman(recipient_public_key);

        // encrypt the surb encryption key using the ephemeral secret
        // TODO: both `iv` and `key` should use a KDF
        let iv = stream_cipher::iv_from_slice::<Aes128Ctr>(&ephemeral_secret[..16]);
        let key = CipherKey::<Aes128Ctr>::from_slice(&ephemeral_secret[16..32]);

        let encrypted_encryption_key =
            stream_cipher::encrypt::<Aes128Ctr>(&key, &iv, &surb_encryption_key.to_bytes());

        // we include 8 bytes of 0x00 as a convenient decryption check
        let encrypted_zeros = stream_cipher::encrypt::<Aes128Ctr>(
            &key,
            &stream_cipher::zero_iv::<Aes128Ctr>(), // all zero IV is fine here; but better use KDF
            &[0u8; 8],
        );

        // our variant header consists of
        // - the public part of the ephemeral key pair: 32 Bytes [^1]
        // - the encrypted surb encryption key: 16 Bytes
        // - the encrypted 0x00...0x00 decryption check : 8 Bytes
        //
        // [^1] Note: for a real-world implementation we would want to blind this using Elligator
        // or similar so that this part of the payload is also indistinguishable from a random
        // string.
        ephemeral_key_pair
            .public_key()
            .to_bytes()
            .into_iter()
            .chain(encrypted_zeros)
            .chain(encrypted_encryption_key)
            .collect::<Vec<_>>()
    }

    /// Returns the expected number of bytes the [`ReplySURB`] will take after serialization.
    /// Useful for deserialization from a bytes stream.
    pub fn serialized_len(mix_hops: u8) -> usize {
        use nym_sphinx_types::{HEADER_SIZE, NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SIZE};

        // the SURB itself consists of SURB_header, first hop address and set of payload keys
        // (note extra 1 for the gateway)
        SurbEncryptionKeySize::USIZE
            + SURB_PUDDING_VARIANT_OVERHEAD
            + HEADER_SIZE
            + NODE_ADDRESS_LENGTH
            + (1 + mix_hops as usize) * PAYLOAD_KEY_SIZE
    }

    pub fn encryption_key(&self) -> &SurbEncryptionKey {
        &self.encryption_key
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // KEY || EXTERNAL_VARIANT_DATA || SURB_BYTES
        self.encryption_key
            .to_bytes()
            .into_iter()
            .chain(self.external_variant_data.clone().into_iter())
            .chain(self.surb.to_bytes().into_iter())
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplySurbError> {
        // TODO: introduce bound checks to guard us against out of bound reads
        let offset_after_encryption_key = SurbEncryptionKeySize::USIZE;
        let offset_after_variant_data = offset_after_encryption_key + SURB_PUDDING_VARIANT_OVERHEAD;

        let encryption_key =
            SurbEncryptionKey::try_from_bytes(&bytes[..offset_after_encryption_key])?;

        let external_variant_data =
            Vec::from(&bytes[offset_after_encryption_key..offset_after_variant_data]);

        let surb = match SURB::from_bytes(&bytes[offset_after_variant_data..]) {
            Err(err) => return Err(ReplySurbError::RecoveryError(err)),
            Ok(surb) => surb,
        };

        Ok(ReplySurb {
            surb,
            encryption_key,
            external_variant_data,
        })
    }

    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.to_bytes()).into_string()
    }

    pub fn from_base58_string<S: Into<String>>(val: S) -> Result<Self, ReplySurbError> {
        let bytes = match bs58::decode(val.into()).into_vec() {
            Ok(decoded) => decoded,
            Err(err) => return Err(ReplySurbError::MalformedStringError(err)),
        };
        Self::from_bytes(&bytes)
    }

    // Allows to optionally increase the packet size to send slightly longer reply.
    // the "used" surb produces the following bytes:
    // note that the `message` argument is expected to already contain all the required parts, i.e.:
    // - surb-ack
    // - key digest
    // - encrypted plaintext with padding to constant length
    pub fn apply_surb<M: AsRef<[u8]>>(
        self,
        message: M,
        packet_size: PacketSize,
        _packet_type: PacketType,
    ) -> Result<(NymPacket, NymNodeRoutingAddress), ReplySurbError> {
        let message_bytes = message.as_ref();
        if message_bytes.len() != packet_size.plaintext_size() {
            eprintln!(
                "{} != {}",
                message_bytes.len(),
                packet_size.plaintext_size()
            );
            return Err(ReplySurbError::UnpaddedMessageError);
        }

        // this can realistically only fail on too long messages and we just checked for that
        let (packet, first_hop) = self
            .surb
            .use_surb(message_bytes, packet_size.payload_size())
            .expect("this error indicates inconsistent message length checking - it shouldn't have happened!");

        let first_hop_address = NymNodeRoutingAddress::try_from(first_hop).unwrap();

        Ok((NymPacket::Sphinx(packet), first_hop_address))
    }
}
