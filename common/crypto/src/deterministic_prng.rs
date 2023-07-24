use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::{rand_core, ChaCha20Rng};
use rand_seeder::Seeder;

/// A PRNG that produces deterministic output given a nonce value.
pub struct DeterministicPRNG {
    rng: ChaCha20Rng,
}

impl DeterministicPRNG {
    pub fn from_nonce(nonce: Vec<u8>) -> Self {
        let rng = ChaCha20Rng::from_seed(Seeder::from(nonce).make_seed());
        DeterministicPRNG { rng }
    }
}

impl CryptoRng for DeterministicPRNG {}

impl RngCore for DeterministicPRNG {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_same_nonce_then_same_output() {
        let mut rng1 = DeterministicPRNG::from_nonce(b"hello".to_vec());
        let mut rng2 = DeterministicPRNG::from_nonce(b"hello".to_vec());

        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u32(), rng2.next_u32());

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn when_different_nonce_then_different_output() {
        let mut rng1 = DeterministicPRNG::from_nonce(b"hello".to_vec());
        let mut rng2 = DeterministicPRNG::from_nonce(b"hellob".to_vec());

        assert_ne!(rng1.next_u64(), rng2.next_u64());
        assert_ne!(rng1.next_u32(), rng2.next_u32());

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_ne!(bytes1, bytes2);
    }
}
