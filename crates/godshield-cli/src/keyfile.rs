// crates/godshield-cli/src/keyfile.rs
//
// ═══════════════════════════════════════════════════════════════════════
// Password-encrypted NEV369 wallet file
//
// One Dilithium5 key, sealed with a password. This is the everyday wallet
// for miners and users; the Shamir vault (`godshield vault create`) is the
// ceremony-grade option for keys that must survive their owner.
//
//   key        = Argon2id(password, salt; 64 MiB, 3 passes, 1 lane) → 32 bytes
//   ciphertext = AES-256-GCM(key, nonce, keypair JSON, aad = address)
//
// Argon2id is memory-hard: each password guess costs 64 MiB of RAM, which
// is what makes an offline attack on a stolen file expensive. The address
// is authenticated as associated data, so editing the address field of a
// wallet file makes decryption fail rather than mislabel the key.
//
// The file holds no plaintext secret. Losing it AND its password loses the
// funds: there is no recovery. That is stated to the user at creation.
// ═══════════════════════════════════════════════════════════════════════

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context};
use argon2::{Algorithm, Argon2, Params, Version};
use godshield_core::GodKeyPair;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub const FORMAT: &str = "nev369-wallet";
pub const MIN_PASSWORD_LEN: usize = 10;

const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct WalletFile {
    pub format: String,
    pub version: u32,
    pub label: String,
    /// Hex Dilithium5 public key — the NEV369 address. Public.
    pub address: String,
    pub created: String,
    pub kdf: Kdf,
    pub cipher: Cipher,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Kdf {
    pub algorithm: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Cipher {
    pub algorithm: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("argon2 parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

impl WalletFile {
    /// Seal `kp` under `password`.
    pub fn seal(kp: &GodKeyPair, password: &str, label: &str) -> anyhow::Result<Self> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("password must be at least {MIN_PASSWORD_LEN} characters");
        }
        let address = hex::encode(&kp.public_key);

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        let key = derive_key(password, &salt, M_COST_KIB, T_COST, P_COST)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| anyhow!("cipher initialisation"))?;
        let plaintext = Zeroizing::new(
            kp.to_json()
                .map_err(|e| anyhow!("serialising key: {e}"))?
                .into_bytes(),
        );
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: address.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;

        Ok(Self {
            format: FORMAT.to_string(),
            version: 1,
            label: label.to_string(),
            address,
            created: chrono::Utc::now().to_rfc3339(),
            kdf: Kdf {
                algorithm: "argon2id".into(),
                m_cost_kib: M_COST_KIB,
                t_cost: T_COST,
                p_cost: P_COST,
                salt_hex: hex::encode(salt),
            },
            cipher: Cipher {
                algorithm: "aes-256-gcm".into(),
                nonce_hex: hex::encode(nonce),
                ciphertext_hex: hex::encode(ciphertext),
            },
        })
    }

    /// Decrypt the key. The key exists only in the returned value — drop it
    /// as soon as it has signed.
    pub fn open(&self, password: &str) -> anyhow::Result<GodKeyPair> {
        if self.format != FORMAT {
            bail!("not a NEV369 wallet file");
        }
        if self.version != 1 {
            bail!("unsupported wallet file version {}", self.version);
        }
        if self.kdf.algorithm != "argon2id" || self.cipher.algorithm != "aes-256-gcm" {
            bail!("unsupported wallet encryption");
        }
        // Bounded so a crafted file cannot make us allocate gigabytes.
        if self.kdf.m_cost_kib > 1024 * 1024 || self.kdf.t_cost > 16 || self.kdf.p_cost > 16 {
            bail!("wallet key-derivation parameters are out of range");
        }
        let salt = hex::decode(&self.kdf.salt_hex).context("wallet salt")?;
        let nonce = hex::decode(&self.cipher.nonce_hex).context("wallet nonce")?;
        let ciphertext = hex::decode(&self.cipher.ciphertext_hex).context("wallet ciphertext")?;
        if nonce.len() != 12 || salt.len() < 8 {
            bail!("wallet file is damaged");
        }

        let key = derive_key(
            password,
            &salt,
            self.kdf.m_cost_kib,
            self.kdf.t_cost,
            self.kdf.p_cost,
        )?;
        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| anyhow!("cipher initialisation"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext[..],
                        aad: self.address.as_bytes(),
                    },
                )
                .map_err(|_| anyhow!("wrong password, or the wallet file is damaged"))?,
        );
        let json = std::str::from_utf8(&plaintext[..]).context("wallet contents")?;
        let kp = GodKeyPair::from_json(json).map_err(|e| anyhow!("wallet key: {e}"))?;
        if hex::encode(&kp.public_key) != self.address {
            bail!("wallet key does not match the address it is labelled with");
        }
        Ok(kp)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
        let w: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a NEV369 wallet file", path.display()))?;
        if w.format != FORMAT {
            bail!("{} is not a NEV369 wallet file", path.display());
        }
        Ok(w)
    }

    /// Write the file, readable by its owner only on Unix. Refuses to
    /// overwrite: replacing a wallet file is how funds get lost.
    pub fn save_new(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .with_context(|| format!("{} already exists or cannot be created", path.display()))?;
        f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_wallet_opens_with_its_password() {
        let kp = GodKeyPair::generate().unwrap();
        let w = WalletFile::seal(&kp, "correct horse battery", "test").unwrap();
        assert_eq!(w.address, hex::encode(&kp.public_key));
        assert!(!w.cipher.ciphertext_hex.is_empty());
        let back = w.open("correct horse battery").unwrap();
        assert_eq!(back.public_key, kp.public_key);
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let kp = GodKeyPair::generate().unwrap();
        let w = WalletFile::seal(&kp, "correct horse battery", "test").unwrap();
        assert!(w.open("wrong horse battery").is_err());
    }

    #[test]
    fn editing_the_address_breaks_decryption() {
        let kp = GodKeyPair::generate().unwrap();
        let mut w = WalletFile::seal(&kp, "correct horse battery", "test").unwrap();
        w.address = hex::encode(&GodKeyPair::generate().unwrap().public_key);
        assert!(w.open("correct horse battery").is_err());
    }

    #[test]
    fn short_passwords_are_rejected() {
        let kp = GodKeyPair::generate().unwrap();
        assert!(WalletFile::seal(&kp, "short", "test").is_err());
    }

    #[test]
    fn the_file_holds_no_plaintext_key() {
        let kp = GodKeyPair::generate().unwrap();
        let w = WalletFile::seal(&kp, "correct horse battery", "test").unwrap();
        let text = serde_json::to_string(&w).unwrap();
        let secret_hex = hex::encode(kp.secret_key_bytes());
        assert!(!text.contains(&secret_hex[64..128]));
    }
}
