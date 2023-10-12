#![allow(dead_code)]
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use rand_core::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// AES key size 256-bits, block size 128 bites.
// two excellent answers on https://crypto.stackexchange.com/
// https://crypto.stackexchange.com/questions/66837/aes-256-gcm-iv-guidelines
// https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
// NIST Special Publication 800-38D, November, 2007
// Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf, section 5.

pub struct FIDataSession {
    pub pr_key: [u8; 32],
    pub pub_key: PublicKey,
    pub nonce: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub shared_nonce: [u8; 32],
    raw_key: [u8; 32],
    fi_data: Vec<u8>,
    gcm_nonce: [u8; 12],
}

impl FIDataSession {
    pub fn new_session(their_pub_key: &PublicKey, their_nonce: &[u8; 32]) -> Self {
        let text = r#"{
    "consentStart": "2019-05-28T11:38:20.380+0000",
    "consentExpiry": "2020-05-28T11:38:20.381+0000",
    "consentMode": "VIEW",
    "fetchType": "ONETIME",
    "consentTypes": [
        "PROFILE",
        "SUMMARY",
        "TRANSACTIONS"
    ],
    "fiTypes": [
        "DEPOSIT",
        "TERM-DEPOSIT"
    ],
    "DataConsumer": {
        "id": "cookiejar-aa@finvu.in",
        "type": "AA"
    },
    "DataProvider": {
        "id": "BARB0KIMXXX",
        "type": "FIP"
    },
    "Customer": {
        "id": "demo@finvu"
    },
    "Accounts": [
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI485964579",
            "maskedAccNumber": "UBI85217881279"
        },
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI4859645",
            "maskedAccNumber": "UBI852178812"
        }
    ],
    "Purpose": {
        "code": "101",
        "refUri": "https://api.rebit.org.in/aa/purpose/101.xml",
        "text": "Wealth management service",
        "Category": {
            "type": "purposeCategoryType"
        }
    },
    "FIDataRange": {
        "from": "2019-05-28T11:38:20.383+0000",
        "to": "2020-05-28T11:38:20.381+0000"
    },
    "DataLife": {
        "unit": "MONTH",
        "value": 4
    },
    "Frequency": {
        "unit": "HOUR",
        "value": 4
    },
    "DataFilter": [
        {
            "type": "TRANSACTIONAMOUNT",
            "operator": ">",
            "value": "20000"
        }
    ]
}"#;
        let pr_key = StaticSecret::random_from_rng(OsRng);
        let pub_key = PublicKey::from(&pr_key);

        let mut nonce: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        // let nonce = Vec::from(key);

        let shared_secret: x25519_dalek::SharedSecret = pr_key.diffie_hellman(their_pub_key);

        let shared_nonce: Vec<u8> = nonce
            .iter()
            .zip(their_nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        let hk = Hkdf::<Sha256>::extract(Some(shared_secret.as_bytes()), &shared_nonce);
        let raw_aes_key: [u8; 32] = hk.0.to_vec().try_into().unwrap();

        let key = Key::<Aes256Gcm>::from(raw_aes_key);
        let cipher = Aes256Gcm::new(&key);
        let aes_gcm_nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let enc_fi_data = cipher.encrypt(&aes_gcm_nonce, text.as_bytes()).unwrap();

        FIDataSession {
            pr_key: *pr_key.as_bytes(),
            pub_key,
            nonce: Vec::from(nonce),
            shared_secret: *shared_secret.as_bytes(),
            shared_nonce: shared_nonce.try_into().unwrap(),
            raw_key: raw_aes_key,
            gcm_nonce: aes_gcm_nonce.try_into().unwrap(),
            fi_data: enc_fi_data,
        }
    }
}

// quick tests
// cargo test ecdhe:: --lib  -- --show-output
#[cfg(test)]
mod ecdhe {
    use super::FIDataSession;
    use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
    use hkdf::Hkdf;
    use rand_core::OsRng;
    use rand_core::RngCore;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn good_key_test_01() {
        let text = r#"{
    "consentStart": "2019-05-28T11:38:20.380+0000",
    "consentExpiry": "2020-05-28T11:38:20.381+0000",
    "consentMode": "VIEW",
    "fetchType": "ONETIME",
    "consentTypes": [
        "PROFILE",
        "SUMMARY",
        "TRANSACTIONS"
    ],
    "fiTypes": [
        "DEPOSIT",
        "TERM-DEPOSIT"
    ],
    "DataConsumer": {
        "id": "cookiejar-aa@finvu.in",
        "type": "AA"
    },
    "DataProvider": {
        "id": "BARB0KIMXXX",
        "type": "FIP"
    },
    "Customer": {
        "id": "demo@finvu"
    },
    "Accounts": [
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI485964579",
            "maskedAccNumber": "UBI85217881279"
        },
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI4859645",
            "maskedAccNumber": "UBI852178812"
        }
    ],
    "Purpose": {
        "code": "101",
        "refUri": "https://api.rebit.org.in/aa/purpose/101.xml",
        "text": "Wealth management service",
        "Category": {
            "type": "purposeCategoryType"
        }
    },
    "FIDataRange": {
        "from": "2019-05-28T11:38:20.383+0000",
        "to": "2020-05-28T11:38:20.381+0000"
    },
    "DataLife": {
        "unit": "MONTH",
        "value": 4
    },
    "Frequency": {
        "unit": "HOUR",
        "value": 4
    },
    "DataFilter": [
        {
            "type": "TRANSACTIONAMOUNT",
            "operator": ">",
            "value": "20000"
        }
    ]
}"#;
        let my_pr_key = EphemeralSecret::random_from_rng(OsRng);
        let my_pub_key = PublicKey::from(&my_pr_key);
        let mut my_nonce: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut my_nonce);
        let my_km = FIDataSession::new_session(&my_pub_key, &my_nonce);
        assert_eq!(my_km.pub_key.as_bytes().len(), 32);
        assert_eq!(my_km.nonce.len(), 32);

        let shared_secret: x25519_dalek::SharedSecret = my_pr_key.diffie_hellman(&my_km.pub_key);
        assert_eq!(shared_secret.as_bytes(), &my_km.shared_secret);

        let shared_nonce: Vec<u8> = my_nonce
            .iter()
            .zip(my_km.nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        assert_eq!(&shared_nonce, &my_km.shared_nonce);

        let hk = Hkdf::<Sha256>::extract(Some(shared_secret.as_bytes()), &shared_nonce);
        let raw_key: [u8; 32] = hk.0.to_vec().try_into().unwrap();
        assert_eq!(raw_key, my_km.raw_key);

        let aes_key = Key::<Aes256Gcm>::from(my_km.raw_key);
        let cipher = Aes256Gcm::new(&aes_key);
        let pt = cipher
            .decrypt(&my_km.gcm_nonce.into(), my_km.fi_data.as_slice())
            .unwrap();
        assert_eq!(pt, text.as_bytes());
        //eprintln!("{:#?}", text)
    }
}
