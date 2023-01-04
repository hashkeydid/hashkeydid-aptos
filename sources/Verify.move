module hashkey::eth_sig_verifier {
    use aptos_std::secp256k1;
    use aptos_std::aptos_hash;
    use std::vector;
    #[test_only]
    use hashkey::utils;
    #[test_only]
    use std::string;
    #[test_only]
    use aptos_std::ed25519;


    const ERR_ETH_INVALID_SIGNATURE_LENGTH : u64 = 4000;
    const ERR_ETH_SIGNATURE_FAIL : u64 = 4001;
    const ERR_ETH_INVALID_PUBKEY  : u64 = 4002;

    fun pubkey_to_address(pk_bytes: vector<u8>): vector<u8> {
        let data = aptos_hash::keccak256(pk_bytes);
        let result = vector::empty<u8>();

        let i = 12;
        while (i < 32) {
            let v = vector::borrow(&data, i);
            vector::push_back(&mut result, *v);
            i = i + 1
        };
        result
    }

    public fun verify_eth_sig(signature: vector<u8>, addr: vector<u8>, message: vector<u8>): bool {
        let signature_length = vector::length(&signature);
        assert!(signature_length == 65, ERR_ETH_INVALID_SIGNATURE_LENGTH);

        let recovery_byte = vector::remove(&mut signature, signature_length - 1);
        assert!(recovery_byte == 27 || recovery_byte == 28, ERR_ETH_SIGNATURE_FAIL);

        let recovery_id = 0;
        if (recovery_byte == 28) {
            recovery_id = 1
        };

        let ecdsa_signature = secp256k1::ecdsa_signature_from_bytes(signature);
        let pk = secp256k1::ecdsa_recover(message, recovery_id, &ecdsa_signature);
        assert!(std::option::is_some(&pk), ERR_ETH_INVALID_PUBKEY);

        let public_key = std::option::borrow(&pk);
        let pk_bytes = secp256k1::ecdsa_raw_public_key_to_bytes(public_key);
        let origin_addr = pubkey_to_address(pk_bytes);
        if (origin_addr == addr) {
            return true
        };

        false
    }

    #[test]
    public fun verify_eth_sig_test() {
        let msg = b"0x5f0D87C9A7D9bF50568a3B57f0f07A0C6a816B24";
        let eth_prefix = b"\x19Ethereum Signed Message:\n";
        let msg_length = vector::length(&msg);
        let sign_origin = vector::empty<u8>();

        vector::append(&mut sign_origin, eth_prefix);
        vector::append(&mut sign_origin, utils::u64_to_vec_u8_string(msg_length));
        vector::append(&mut sign_origin, msg);
        let msg_hash = aptos_hash::keccak256(copy sign_origin);

        let str = string::utf8(b"58c52a10745d569b58a71888076b32e429760774026754c5995b5049a451d01662ae294a2c54ce559191780ea4a1d06595999bcef2214728562351b393abf0f41c");
        let address_bytes = x"5f0D87C9A7D9bF50568a3B57f0f07A0C6a816B24";

        let sig = utils::string_to_vector_u8(&str);

        assert!(verify_eth_sig(sig, address_bytes, msg_hash), 101);
    }

    #[test]
    public fun ed25519_sign_verify_test() {
        let msg = b"test";
        let sig_bytes = x"375705c3f9c06aac0df7c01d0a84ff8009cc4cef2171f35c1cb4fa3e5e571ca42bdefa8bc200ba7ba05de4ee2ae329112f293673e2b345a3bbf76d77f38c240d";
        let pubkey_bytes = x"400b8451e6630047ffe3e0b3e38730d6c8ecc8694b6c285879a6cd3019eb03cd";

        let pk = ed25519::new_validated_public_key_from_bytes(pubkey_bytes);
        let pk = std::option::extract(&mut pk);
        let pk = ed25519::public_key_into_unvalidated(pk);
        let sig = ed25519::new_signature_from_bytes(sig_bytes);

        assert!(ed25519::signature_verify_strict(&sig, &pk, msg), 102);
    }
}