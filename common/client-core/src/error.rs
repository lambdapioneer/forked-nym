// Copyright 2022 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use nym_crypto::asymmetric::identity::Ed25519RecoveryError;
use nym_gateway_client::error::GatewayClientError;
use nym_topology::gateway::GatewayConversionError;
use nym_topology::NymTopologyError;
use nym_validator_client::ValidatorClientError;
use std::error::Error;

#[derive(thiserror::Error, Debug)]
pub enum ClientCoreError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Gateway client error: {0}")]
    GatewayClientError(#[from] GatewayClientError),

    #[error("Ed25519 error: {0}")]
    Ed25519RecoveryError(#[from] Ed25519RecoveryError),

    #[error("Validator client error: {0}")]
    ValidatorClientError(#[from] ValidatorClientError),

    #[error("No gateway with id: {0}")]
    NoGatewayWithId(String),

    #[error("No gateways on network")]
    NoGatewaysOnNetwork,

    #[error("Failed to setup gateway")]
    FailedToSetupGateway,

    #[error("List of nym apis is empty")]
    ListOfNymApisIsEmpty,

    #[error("Could not load existing gateway configuration: {0}")]
    CouldNotLoadExistingGatewayConfiguration(std::io::Error),

    #[error("The current network topology seem to be insufficient to route any packets through")]
    InsufficientNetworkTopology(#[from] NymTopologyError),

    #[error("experienced a failure with our reply surb persistent storage: {source}")]
    SurbStorageError {
        source: Box<dyn Error + Send + Sync>,
    },

    #[error("experienced a failure with our cryptographic keys persistent storage: {source}")]
    KeyStoreError {
        source: Box<dyn Error + Send + Sync>,
    },

    #[error("experienced a failure with our gateway details storage: {source}")]
    GatewayDetailsStoreError {
        source: Box<dyn Error + Send + Sync>,
    },

    #[error("The gateway id is invalid - {0}")]
    UnableToCreatePublicKeyFromGatewayId(Ed25519RecoveryError),

    #[error("The identity of the gateway is unknown - did you run init?")]
    GatewayIdUnknown,

    #[error("The owner of the gateway is unknown - did you run init?")]
    GatewayOwnerUnknown,

    #[error("The address of the gateway is unknown - did you run init?")]
    GatewayAddressUnknown,

    #[error("The gateway is malformed: {source}")]
    MalformedGateway {
        #[from]
        source: GatewayConversionError,
    },

    #[error("failed to establish connection to gateway: {source}")]
    GatewayConnectionFailure {
        #[from]
        source: tungstenite::Error,
    },

    #[cfg(target_arch = "wasm32")]
    #[error("failed to establish gateway connection (wasm)")]
    GatewayJsConnectionFailure,

    #[error("Gateway connection was abruptly closed")]
    GatewayConnectionAbruptlyClosed,

    #[error("Timed out while trying to establish gateway connection")]
    GatewayConnectionTimeout,

    #[error("No ping measurements for the gateway ({identity}) performed")]
    NoGatewayMeasurements { identity: String },

    #[error("failed to register receiver for reconstructed mixnet messages")]
    FailedToRegisterReceiver,

    #[error("Unexpected exit")]
    UnexpectedExit,

    #[error(
        "This operation would have resulted in clients keys being overwritten without permission"
    )]
    ForbiddenKeyOverwrite,

    #[error("gateway details are unavailable")]
    UnavailableGatewayDetails {
        source: Box<dyn Error + Send + Sync>,
    },

    #[error("gateway shared key is unavailable whilst we have full node information")]
    UnavailableSharedKey,

    #[error("attempted to obtain fresh gateway details whilst already knowing about one")]
    UnexpectedGatewayDetails,

    #[error("the provided gateway details (for gateway {gateway_id}) do not correspond to the shared keys")]
    MismatchedGatewayDetails { gateway_id: String },
}

/// Set of messages that the client can send to listeners via the task manager
#[derive(thiserror::Error, Debug)]
pub enum ClientCoreStatusMessage {
    // NOTE: The nym-connect frontend listens for these strings, so don't change them until we have a more robust mechanism in place
    #[error("The connected gateway is slow, or the connection to it is slow")]
    GatewayIsSlow,
    // NOTE: The nym-connect frontend listens for these strings, so don't change them until we have a more robust mechanism in place
    #[error("The connected gateway is very slow, or the connection to it is very slow")]
    GatewayIsVerySlow,
}
