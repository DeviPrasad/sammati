#[cfg(test)]
mod encode {
    use data_encoding::BASE64;
    use dull::hex;

    #[test]
    fn hex_to_base64() {
        let raw: [u8; 32] =
            hex::decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let b64 = BASE64.encode(raw.as_ref());
        eprint!("base64: {b64:}");
    }
}
