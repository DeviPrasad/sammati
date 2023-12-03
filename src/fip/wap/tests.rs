// quick test
// curl -v -H"Accept: application/json" -X GET http://fip-wap.sammati.web3pleb.org:40601/Heartbeat
// curl -v -H"Content-Type: application/json" -X POST http://fip-wap.sammati.web3pleb.org:40601/FI/fetch
//
#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use dull::jwa::SignatureAlgorithm;
    use dull::jws::JWSigner;
    use dull::jwt::JwsHeaderBuilder;
    use dull::nickel::NickelKeyStore;
    use dull::webkey::{KeyDesc, KeyStore};
    use serde::{Deserialize, Serialize};

    use common::ts::UtcTs;
    use common::types::HealthOkResp;
    use common::types::{Empty, ServiceHealthStatus};

    #[test]
    fn simple_ok_response() {
        let resp: HealthOkResp<Empty> =
            HealthOkResp::<Empty>::v2(&UtcTs::now(), ServiceHealthStatus::DOWN, None);
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)));
    }

    #[test]
    fn simple_ok_response_round_trip() {
        let serialized_okr = serde_json::to_string(&HealthOkResp::<Empty>::v2(
            &UtcTs::now(),
            ServiceHealthStatus::DOWN,
            Some(Empty::default()),
        ));
        let okr_json_str: String = serialized_okr.unwrap();
        //eprintln!("json = {}", okr_json_str);
        let deserialized_okr = serde_json::from_str(&okr_json_str);
        //eprintln!("serialization result = {:#?}", deserialized_okr);
        let okr: HealthOkResp<Empty> = deserialized_okr.unwrap();
        //eprintln!("version = {:#?}", okr);
        assert_eq!(okr.ver, "2.0.0");
        let serialized_okr_2 = serde_json::to_string(&okr);
        //eprintln!("json = {:#?}", serialized_okr_2);
        assert_eq!(okr_json_str, serialized_okr_2.unwrap())
    }

    const FIP_WAP_HS512_KID_01: &str = "GRVj3Kqoq2Qe7WLqI0dKSecjMJdcpLOaXVXfwQekkDc";
    const FIP_WAP_HS512_KEY: &str =
        "x4w7vzRFbvbrZ1IArIKKDgHQ3p6XC7CF5AowbojVCbcQIgexHwefDrYyUw0T43hnWsBJBcj5jD11hPgBHCJXIQ";

    #[test]
    fn simple_ok_response_custom() {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct FipNode {
            pid: String,
            tid: String,
            url: String,
        }
        impl Default for FipNode {
            fn default() -> Self {
                FipNode {
                    pid: format!("pid_{:?}", std::process::id()),
                    tid: format!("tid_{:?}", std::thread::current().id()),
                    url: "https://fip-wap.sammati.in/Heartbeat".to_string(),
                }
            }
        }
        let resp: HealthOkResp<FipNode> = HealthOkResp::<FipNode>::v2(
            &UtcTs::now(),
            ServiceHealthStatus::DOWN,
            Some(FipNode::default()),
        );
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)))
    }

    const SAMMATI_AA_ES256_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"#;
    const SAMMATI_AA_ES256_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;
    const KID_SAMMATI_AA_ES256_PRIVATE_KEY: &str = "vPfRqE60B33tzVlF5E6OA2mKK17sGRXsfrI9obBEjL5";
    const KID_SAMMATI_AA_ES256_PUBLIC_KEY: &str = "RP4J7WDWoT-JP00a81lOIn-6q1LkscQ-r-IoyWPS-Nk";

    #[test]
    pub fn test_unencoded_sammati_accounts_link_ed25519() {
        let ed25519_pub_key_pem_02 = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+hf401REYXC81NHtQr9PfEQh0SXNE1vng+WRqT8CRvg=
-----END PUBLIC KEY-----"#;
        let ed25519_pr_key_pem_02 = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILISPPYTpXnbOO1z7CyMOM32H5Mw0VmMsstn36dH0l+P
-----END PRIVATE KEY-----"#;
        let mut nks = NickelKeyStore::default();
        const KID_ED25519_PUBLIC_KEY_02: &str = "KICAgICAgICAgICAgInVuaXQiOiAiTU9OVEgiLA0KIC";
        const KID_ED25519_PRIVATE_KEY_02: &[u8] = br#"B7DQogICAgICAgICAgICAgICAgInR5cGUiOiAicHVyc"#;
        {
            let ks: &mut dyn KeyStore = &mut nks;
            let res = ks.add_sig_ed25519_private_key_pem(
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
                ed25519_pr_key_pem_02,
            );
            assert!(res);
            let res = ks.add_sig_ed25519_public_key_pem(
                &String::from_utf8(KID_ED25519_PUBLIC_KEY_02.into()).unwrap(),
                ed25519_pub_key_pem_02,
            );
            assert!(res);
            let res = ks.add_sig_hmac_key(
                dull::jwa::SignatureAlgorithm::HS512,
                FIP_WAP_HS512_KID_01,
                FIP_WAP_HS512_KEY.as_bytes(),
            );
            assert!(res);
            let res = ks.add_sig_ec_private_key_pem(
                dull::jwa::SignatureAlgorithm::ES256,
                KID_SAMMATI_AA_ES256_PRIVATE_KEY,
                SAMMATI_AA_ES256_PRIVATE_KEY,
            );
            assert!(res);
            let res = ks.add_sig_ec_public_key_pem(
                dull::jwa::SignatureAlgorithm::ES256,
                KID_SAMMATI_AA_ES256_PUBLIC_KEY,
                SAMMATI_AA_ES256_PUBLIC_KEY,
            );
            assert!(res);
        }
        let jws = JWSigner::for_nickel(&nks);
        let accounts_link_req_json = br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Customer":{"id":"sammati.in/aa/uid/62415273490451973263","Accounts":[{"FIType":"DEPOSIT","accType":"SAVINGS","accRefNumber":"NADB0000570926453147364217812345","maskedAccNumber":"XXXXXXXXXXXXX0753468"},{"FIType":"DEPOSIT","accType":"SAVINGS","accRefNumber":"NADB0000570926453147364217812345","maskedAccNumber":"XXXXXXXXXXXXX2853165"}]}}"#;
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            // sign
            let ds = jws.sign(&kd, &header_ed25519, accounts_link_req_json);
            // let jws = jws.sign(&kd, &header, consent_req_json);
            if ds.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_ed25519 - unencoded-jws[1] {:#?}",
                    ds
                );
            }
            assert!(ds.is_ok());
            /*let ds = ds.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(ds.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_link_req_json);
            // let jws = jws.sign(&kd, &header, consent_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        let accounts_delink_req_json=br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Account":{"customerAddress":"sammati.in/aa/uid/62415273490451973263","linkRefNumber":"14c3c1ee8b7a8e54fef456c4d6eb7b2b"}}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_delink_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_delink_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_delink_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, accounts_delink_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_delink_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_delink_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        let accounts_link_verify_req_json=br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-351804dfcdc5","refNumber":"mNyaXQiOlsiYjY0Il0sImtpZCItJQ0Fn","token":"165023"}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_link_verify_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_verify_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_verify_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, accounts_link_verify_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_verify_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_verify_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        //
        let fi_req_json=br#"{"ver":"2.0.0","timestamp":"2023-11-13T19:01:05.505Z","txnid":"fcd8ca5c-f791-4a4f-967e-fc8a5a34a93d","Consent":{"id":"cid_eLQuFAB1QRyWY_DHYxUX4Q","digitalSignature":"O3KPh-eTpW2w47QXYidOBe1Hk2y7djVAEcOnZyRRvxQ3cY18-9ZWiodF16jff-e7yNQgsYZpAy95Fx2Fft8LoYugkYh9_6qHiG_7LCtW8Ng4nCMgZM3Wwsj11ks1msrK5C1ksPrGlTkFhm9-FufNkPTAlW76_5Sb8G_lOsIj1lB8TrvKpOvPlhEIgsS4WBNdPfv3SBqTV2suw2LvkX3QTilqwuMgXMkrm9-RYL90fweX_yyoyaBWHOJNQaKNuQWPpoRRNHGOx3v4_QiwgrELdfeTVtKn6R_AsfaBoEthQ3wrc8tY1q0Wx5j0x18NdU2R2C26dHyZ9M11dEH99psA1A"},"FIDataRange":{"from":"2023-04-01T00:00:00.000Z","to":"2024-03-31T23:59:59.000Z"},"KeyMaterial":{"cryptoAlg":"ECDH","curve":"X25519","params":"cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH","DHPublicKey":{"expiry":"2024-04-01T00:00:00.000Z","Parameters":"publicKeyEncoding=HEX;nonceEncoding=HEX;nonceLen=12","KeyValue":"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"},"Nonce":"46474a88a0c66a38e70c0629"}}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let signing_kd =
                KeyDesc::from_alg_kid(SignatureAlgorithm::ES256, KID_SAMMATI_AA_ES256_PRIVATE_KEY);
            let header_es256_pub = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::ES256)
                .unencoded()
                .kid(KID_SAMMATI_AA_ES256_PUBLIC_KEY)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&signing_kd, &header_es256_pub, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_es256 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_es256 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        //
        //
        let fi_fetch_req_json=br#"{"ver":"2.0.0","timestamp":"2023-11-23T19:23:05.505Z","txnid":"fcd8ca5c-f791-4a4f-967e-fc8a5a34a93d","sessionId":"zfjGs2BVS9GQq4imZzpuig","fipId":"fip_a32ef1af-18c0-471d-b494-6e918fa8ba00_AlphaDigiFinBank","linkRefNumber":["SqrVhuCsQlmoiiIn5Pgpiw","R_0tJRgqQDGGVT4kXFli_A"]}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, fi_fetch_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_fetch_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_fetch_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, fi_fetch_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_fetch_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_fetch_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
    }
}
