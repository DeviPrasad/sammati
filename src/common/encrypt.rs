use data_encoding::BASE64;
use dull::{
    aead::{self, Aead},
    hkdf, x25519,
};
use serde::{Deserialize, Serialize};

use crate::{mutter::Mutter, ts::UtcTs, types::PeerType};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataFIUserContext {
    pub km_params: String,
    pub dh_params: String,
    pub peer_type: PeerType,
    pub peer_id: String,
    pub root_tx_id: String,
    pub consent_id: String,
    pub fip_id: String,
    pub fiu_dh_pub_key: Vec<u8>,
    pub kd_nonce: Vec<u8>,
    pub cipher_nonce: Vec<u8>,
}

impl DataFIUserContext {
    pub fn from(
        km_params: &str,
        dh_params: &str,
        peer_type: PeerType,
        peer_id: &str,
        tx_id: &str,
        consent_id: &str,
        fip_id: &str,
        dh_pub_key: Vec<u8>,
        kd_nonce: Vec<u8>,
        cipher_nonce: Vec<u8>,
    ) -> Self {
        Self {
            km_params: km_params.to_owned(),
            dh_params: dh_params.to_owned(),
            peer_type,
            peer_id: peer_id.to_owned(),
            root_tx_id: tx_id.to_owned(),
            consent_id: consent_id.to_owned(),
            fip_id: fip_id.to_owned(),
            fiu_dh_pub_key: dh_pub_key,
            kd_nonce: kd_nonce,
            cipher_nonce: cipher_nonce,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedData {
    pub km_params_desc_str: String,
    pub dh_params_desc_str: String,
    pub root_tx_id: String,
    pub consent_id: String,
    pub fip_id: String,
    pub dh_pub_key: Vec<u8>,
    pub kd_nonce: Vec<u8>,
    pub kd_info: Vec<u8>,
    pub cipher_nonce: Vec<u8>,
    pub data: Vec<u8>,
}

pub struct DataEncryptor {}

impl DataEncryptor {
    pub fn encrypt(data: Vec<u8>, ctx: &DataFIUserContext) -> Result<EncryptedData, Mutter> {
        let peer_kd_nonce: Vec<u8> = BASE64.decode(&ctx.kd_nonce).map_err(|_| {
            eprintln!("kd_nonce not valid base64 {}\n", ctx.kd_nonce.len());
            Mutter::DatEncryptionError
        })?;
        if peer_kd_nonce.len() != 32 {
            eprintln!(
                "peer_kd_nonce size wrong. expecting 32 bytes, found {}\n",
                peer_kd_nonce.len()
            );
            return Err(Mutter::DatEncryptionError);
        }
        let fip_kd_nonce: Vec<u8> = dull::jwa::random_bytes(32);
        let common_kd_nonce: Vec<u8> = fip_kd_nonce
            .iter()
            .zip(peer_kd_nonce)
            .map(|(x, y)| x ^ y)
            .collect();

        let dh_peer_pub_key: Vec<u8> = BASE64.decode(&ctx.fiu_dh_pub_key).map_err(|_| {
            eprintln!(
                "fiu_dh_pub_key not valid base64 {}\n",
                ctx.fiu_dh_pub_key.len()
            );
            Mutter::DatEncryptionError
        })?;
        if dh_peer_pub_key.len() != 32 {
            eprintln!(
                "dh_peer_pub_key size wrong. expecting 32 bytes, found {}\n",
                dh_peer_pub_key.len()
            );
            return Err(Mutter::DatEncryptionError);
        }
        let dh_peer_pub_key: x25519::PublicKey = x25519::PublicKey::from_bytes(dh_peer_pub_key)
            .map_err(|_e| {
                eprintln!("x25519::PublicKey::from_bytes error {_e:#?}\n");
                Mutter::DatEncryptionError
            })?;

        let fip_dh_key_pair: x25519::KeyPair = x25519::KeyPair::new();
        let dh_shared_secret: x25519::SharedSecret =
            fip_dh_key_pair.dh(&dh_peer_pub_key).map_err(|_e| {
                eprintln!("fip_dh_key_pair::dh error {_e:#?}\n");
                Mutter::DatEncryptionError
            })?;
        log::warn!(
            "common_kd_nonce: {:#?}, fip_kd_nonce: {:#?}, dh_shared_secret: {:#?}",
            BASE64.encode(&common_kd_nonce),
            BASE64.encode(&fip_kd_nonce),
            BASE64.encode(&dh_shared_secret.0)
        );
        let kd_info = [
            b"|",
            ctx.root_tx_id.as_bytes(),
            b"|",
            ctx.consent_id.as_bytes(),
            b"|",
            ctx.fip_id.as_bytes(),
            b"|",
            UtcTs::now().to_string().as_bytes(),
            b"|",
        ]
        .concat();
        log::warn!("kd_info: {:#?}", BASE64.encode(&kd_info));
        let aes_key: hkdf::PRK<32> = hkdf::HKDF::<32>::derive(
            &dh_shared_secret.raw(),
            Some(&common_kd_nonce),
            &kd_info,
            hkdf::MACAlg::SHA256,
        )
        .map_err(|_e| {
            eprintln!("fhkdf::HKDF::<32>::derive error {_e:#?}\n");
            Mutter::DatEncryptionError
        })?;
        let aead_key = aes_key.take();
        log::warn!("aead key: {:#?}", BASE64.encode(&aead_key));
        let fip_aes_nonce = [0u8; 12];
        let aead: aead::AesGcm<32> =
            aead::Aes256Gcm::try_from(aead_key).map_err(|_e| Mutter::DatEncryptionError)?;
        let encrypted_data: Vec<u8> =
            aead.encrypt(&data, &kd_info, &fip_aes_nonce)
                .map_err(|_e| {
                    eprintln!("aead.encrypt error {_e:#?}\n");
                    Mutter::DatEncryptionError
                })?;

        Ok(EncryptedData {
            km_params_desc_str: ctx.km_params.to_owned(),
            dh_params_desc_str: ctx.dh_params.to_owned(),
            dh_pub_key: fip_dh_key_pair.public_key().0.into(),
            kd_nonce: fip_kd_nonce.to_owned(),
            cipher_nonce: fip_aes_nonce.into(),
            root_tx_id: ctx.root_tx_id.to_owned(),
            consent_id: ctx.consent_id.to_owned(),
            fip_id: ctx.fip_id.to_owned(),
            kd_info: kd_info,
            data: encrypted_data,
        })
    }
}

#[cfg(test)]
mod encode {
    use data_encoding::BASE64;
    use dull::hex;

    #[test]
    fn hex_to_base64() {
        let raw_key: [u8; 32] =
            hex::decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let b64_key = BASE64.encode(raw_key.as_ref());
        eprint!("public_ky base64: {b64_key:}\n");
        assert_eq!(b64_key, "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=");

        let nonce = dull::jwa::random_bytes(32);
        let b64_nonce = BASE64.encode(nonce.as_ref());
        eprint!("nonce base64: {b64_nonce:}\n");
        assert_eq!(b64_nonce.len(), 44);
    }
}
