
module hashkey::Verifier {
    use aptos_std::secp256k1;
    use aptos_std::aptos_hash;
    use std::vector;

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
        assert!(recovery_byte == 0 || recovery_byte == 1, ERR_ETH_SIGNATURE_FAIL);

        let ecdsa_signature = secp256k1::ecdsa_signature_from_bytes(signature);
        let pk = secp256k1::ecdsa_recover(message, recovery_byte, &ecdsa_signature);
        assert!(std::option::is_some(&pk), ERR_ETH_INVALID_PUBKEY);

        let public_key = std::option::borrow(&pk);
        let pk_bytes = secp256k1::ecdsa_raw_public_key_to_bytes(public_key);
        let origin_addr = pubkey_to_address(pk_bytes);
        if (origin_addr == addr) {
            return true
        };

        false
    }
}