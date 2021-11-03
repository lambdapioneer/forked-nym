// due to code generated by JsonSchema
#![allow(clippy::field_reassign_with_default)]

use crate::{IdentityKey, SphinxKey};
use cosmwasm_std::{coin, Addr, Coin};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::cmp::Ordering;
use std::fmt::Display;
use ts_rs::TS;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize, JsonSchema, TS)]
pub struct MixNode {
    pub host: String,
    pub mix_port: u16,
    pub verloc_port: u16,
    pub http_api_port: u16,
    pub sphinx_key: SphinxKey,
    /// Base58 encoded ed25519 EdDSA public key.
    pub identity_key: IdentityKey,
    pub version: String,
}

#[derive(
    Copy, Clone, Debug, Serialize_repr, PartialEq, PartialOrd, Deserialize_repr, JsonSchema,
)]
#[repr(u8)]
pub enum Layer {
    Gateway = 0,
    One = 1,
    Two = 2,
    Three = 3,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct MixNodeBond {
    pub bond_amount: Coin,
    pub total_delegation: Coin,
    pub owner: Addr,
    pub layer: Layer,
    pub block_height: u64,
    pub mix_node: MixNode,
}

impl MixNodeBond {
    pub fn new(
        bond_amount: Coin,
        owner: Addr,
        layer: Layer,
        block_height: u64,
        mix_node: MixNode,
    ) -> Self {
        MixNodeBond {
            total_delegation: coin(0, &bond_amount.denom),
            bond_amount,
            owner,
            layer,
            block_height,
            mix_node,
        }
    }

    pub fn identity(&self) -> &String {
        &self.mix_node.identity_key
    }

    pub fn bond_amount(&self) -> Coin {
        self.bond_amount.clone()
    }

    pub fn owner(&self) -> &Addr {
        &self.owner
    }

    pub fn mix_node(&self) -> &MixNode {
        &self.mix_node
    }
}

impl PartialOrd for MixNodeBond {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // first remove invalid cases
        if self.bond_amount.denom != self.total_delegation.denom {
            return None;
        }

        if other.bond_amount.denom != other.total_delegation.denom {
            return None;
        }

        if self.bond_amount.denom != other.bond_amount.denom {
            return None;
        }

        // try to order by total bond + delegation
        let total_cmp = (self.bond_amount.amount + self.total_delegation.amount)
            .partial_cmp(&(self.bond_amount.amount + self.total_delegation.amount))?;

        if total_cmp != Ordering::Equal {
            return Some(total_cmp);
        }

        // then if those are equal, prefer higher bond over delegation
        let bond_cmp = self
            .bond_amount
            .amount
            .partial_cmp(&other.bond_amount.amount)?;
        if bond_cmp != Ordering::Equal {
            return Some(bond_cmp);
        }

        // then look at delegation (I'm not sure we can get here, but better safe than sorry)
        let delegation_cmp = self
            .total_delegation
            .amount
            .partial_cmp(&other.total_delegation.amount)?;
        if delegation_cmp != Ordering::Equal {
            return Some(delegation_cmp);
        }

        // then check block height
        let height_cmp = self.block_height.partial_cmp(&other.block_height)?;
        if height_cmp != Ordering::Equal {
            return Some(height_cmp);
        }

        // finally go by the rest of the fields in order. It doesn't really matter at this point
        // but we should be deterministic.
        let owner_cmp = self.owner.partial_cmp(&other.owner)?;
        if owner_cmp != Ordering::Equal {
            return Some(owner_cmp);
        }

        let layer_cmp = self.layer.partial_cmp(&other.layer)?;
        if layer_cmp != Ordering::Equal {
            return Some(layer_cmp);
        }

        self.mix_node.partial_cmp(&other.mix_node)
    }
}

impl Display for MixNodeBond {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "amount: {} {}, owner: {}, identity: {}",
            self.bond_amount.amount, self.bond_amount.denom, self.owner, self.mix_node.identity_key
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct PagedMixnodeResponse {
    pub nodes: Vec<MixNodeBond>,
    pub per_page: usize,
    pub start_next_after: Option<IdentityKey>,
}

impl PagedMixnodeResponse {
    pub fn new(
        nodes: Vec<MixNodeBond>,
        per_page: usize,
        start_next_after: Option<IdentityKey>,
    ) -> Self {
        PagedMixnodeResponse {
            nodes,
            per_page,
            start_next_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, JsonSchema)]
pub struct MixOwnershipResponse {
    pub address: Addr,
    pub has_node: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mixnode_fixture() -> MixNode {
        MixNode {
            host: "1.1.1.1".to_string(),
            mix_port: 123,
            verloc_port: 456,
            http_api_port: 789,
            sphinx_key: "sphinxkey".to_string(),
            identity_key: "identitykey".to_string(),
            version: "0.11.0".to_string(),
        }
    }

    #[test]
    fn mixnode_bond_partial_ord() {
        let _150foos = Coin::new(150, "foo");
        let _50foos = Coin::new(50, "foo");
        let _0foos = Coin::new(0, "foo");

        let mix1 = MixNodeBond {
            bond_amount: _150foos.clone(),
            total_delegation: _50foos.clone(),
            owner: Addr::unchecked("foo1"),
            layer: Layer::One,
            block_height: 100,
            mix_node: mixnode_fixture(),
        };

        let mix2 = MixNodeBond {
            bond_amount: _150foos.clone(),
            total_delegation: _50foos.clone(),
            owner: Addr::unchecked("foo2"),
            layer: Layer::One,
            block_height: 120,
            mix_node: mixnode_fixture(),
        };

        let mix3 = MixNodeBond {
            bond_amount: _50foos,
            total_delegation: _150foos.clone(),
            owner: Addr::unchecked("foo3"),
            layer: Layer::One,
            block_height: 120,
            mix_node: mixnode_fixture(),
        };

        let mix4 = MixNodeBond {
            bond_amount: _150foos.clone(),
            total_delegation: _0foos.clone(),
            owner: Addr::unchecked("foo4"),
            layer: Layer::One,
            block_height: 120,
            mix_node: mixnode_fixture(),
        };

        let mix5 = MixNodeBond {
            bond_amount: _0foos,
            total_delegation: _150foos,
            owner: Addr::unchecked("foo5"),
            layer: Layer::One,
            block_height: 120,
            mix_node: mixnode_fixture(),
        };

        // summary:
        // mix1: 150bond + 50delegation, foo1, 100
        // mix2: 150bond + 50delegation, foo2, 120
        // mix3: 50bond + 150delegation, foo3, 120
        // mix4: 150bond + 0delegation, foo4, 120
        // mix5: 0bond + 150delegation, foo5, 120

        // highest total bond+delegation is used
        // then bond followed by delegation
        // finally just the rest of the fields

        // mix1 has higher total than mix4 or mix5
        assert!(mix1 > mix4);
        assert!(mix1 > mix5);

        // mix1 has the same total as mix3, however, mix1 has more tokens in bond
        assert!(mix1 > mix3);
        // same case for mix4 and mix5
        assert!(mix4 > mix5);

        // same bond and delegation, so it's just ordered by height
        assert!(mix1 < mix2);
    }
}
