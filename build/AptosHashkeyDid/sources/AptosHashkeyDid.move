module hashkey::AptosHashkeyDid {
    use std::signer;
    use std::vector;
    use std::bcs;
    use std::string::{Self, String};

    use aptos_std::aptos_hash;
    use aptos_std::simple_map::{Self, SimpleMap};
    use aptos_token_objects::aptos_token;

    use aptos_framework::account;
    use aptos_framework::timestamp;
    use aptos_framework::coin::Self;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::event::{Self, EventHandle};

    use aptos_std::secp256k1;

    ///
    /// Errors
    ///
    const ERROR_NOT_OWNER: u64 = 0;
    const ERROR_DID_CLAIMED: u64 = 1;
    const ERROR_ADDR_CLAIMED: u64 = 2;
    const ERROR_INVALID_SIGNATURE: u64 = 3;
    const ERROR_INVALID_ARGUMENT: u64 = 4;
    const ERROR_INVALID_DID_FORMAT: u64 = 5;
    const ERR_ETH_INVALID_SIGNATURE_LENGTH : u64 = 6;
    const ERR_ETH_SIGNATURE_FAIL : u64 = 7;
    const ERR_ETH_INVALID_PUBKEY  : u64 = 8;
    ///
    /// Data structures

    struct State has key {
        addrClaimed: SimpleMap<address, bool>,
        didClaimed: SimpleMap<string::String, bool>,
        tokenIdToDid: SimpleMap<u256, string::String>,
        didToTokenId: SimpleMap<string::String, u256>,
        ownerOf: SimpleMap<u256, address>,
        resource_cap: account::SignerCapability,
        resource_addr: address,
        owner_addr: address,
        mint_events: EventHandle<MintEvent>,
        send_events: EventHandle<SendEvent>,
    }

    /// 
    /// Seed
    /// 
    const HASHKEY_SEED: vector<u8> = b"AptosHashkeyDid";
    const ETH_SIGNER_ADDRESS: vector<u8> = x"ae9b9373C1E2Af3b6F8Ba0312fbC51F3AfFDF318";
    //
    // Events
    //
    struct MintEvent has store, drop {
        owner: address,
        token_id: u256,
        uri: String,
        timestamp: u64
    }

    struct SendEvent has store, drop {
        sender: address,
        dst_chain_id: u64,
        receiver: vector<u8>,
        token_id: u256,
        did: String,
        timestamp: u64
    }

    //
    // Entry functions
    //
    fun init_module(sender:&signer) {
        let (resource_signer,resource_signer_cap) = account::create_resource_account(sender, HASHKEY_SEED);

        move_to(sender, State {
            addrClaimed: simple_map::create<address, bool>(),
            didClaimed: simple_map::create<string::String, bool>(),
            tokenIdToDid: simple_map::create<u256, string::String>(),
            didToTokenId: simple_map::create<string::String, u256>(),
            ownerOf: simple_map::create<u256, address>(),
            resource_cap: resource_signer_cap,
            resource_addr: signer::address_of(&resource_signer),
            owner_addr: signer::address_of(sender),
            mint_events: account::new_event_handle<MintEvent>(&resource_signer),
            send_events: account::new_event_handle<SendEvent>(&resource_signer),
        });

        aptos_token::create_collection(
            &resource_signer,
            string::utf8(b"Kindle your Web3 highlights and achievements on-chain."),
            100000,
            string::utf8(b"Hashkey DID"), 
            string::utf8(b"https://hashkey.4everland.store/metadata/0"),
            false,  // mutable_description
            false,  // mutable_royalty
            false,  // mutable_uri
            false,  // mutable_token_description
            false,  // mutable_token_name
            false,  // mutable_token_properties
            false,  // mutable_token_uri
            true,  // tokens_burnable_by_creator
            true,  // tokens_freezable_by_creator
            1,  // royalty_numerator
            10,  // royalty_denominator
        );
    }

    public entry fun mintDid(receiver: &signer, did: string::String, tokenId: u256, expiredTimestamp: u256, signature: vector<u8>) acquires State {
        assert!(verifyDIDFormat(*string::bytes(&did)), ERROR_INVALID_DID_FORMAT);
        let receiver_addr = signer::address_of(receiver);
        let message = vector::empty<u8>();
        vector::append(&mut message, bcs::to_bytes<address>(&receiver_addr));
        let chainId = 2;
        vector::append(&mut message, bcs::to_bytes<u256>(&chainId));
        vector::append(&mut message, bcs::to_bytes<u256>(&expiredTimestamp));
        vector::append(&mut message, bcs::to_bytes<String>(&did));
        vector::append(&mut message, bcs::to_bytes<u256>(&tokenId));
        let msg_hash = aptos_hash::keccak256(copy message);
        assert!(verify_eth_sig(signature, ETH_SIGNER_ADDRESS, msg_hash), ERROR_INVALID_SIGNATURE);

        mint_internal(receiver_addr, did, tokenId);
    }

    public entry fun syncMint(receiver_addr: address, did: string::String, tokenId: u256, expiredTimestamp: u256, signature: vector<u8>) acquires State {
        assert!(verifyDIDFormat(*string::bytes(&did)), ERROR_INVALID_DID_FORMAT);
        let message = vector::empty<u8>();
        vector::append(&mut message, bcs::to_bytes<address>(&receiver_addr));
        let chainId = 2;
        vector::append(&mut message, bcs::to_bytes<u256>(&chainId));
        vector::append(&mut message, bcs::to_bytes<u256>(&expiredTimestamp));
        vector::append(&mut message, bcs::to_bytes<String>(&did));
        vector::append(&mut message, bcs::to_bytes<u256>(&tokenId));
        let msg_hash = aptos_hash::keccak256(copy message);
        assert!(verify_eth_sig(signature, ETH_SIGNER_ADDRESS, msg_hash), ERROR_INVALID_SIGNATURE);

        mint_internal(receiver_addr, did, tokenId);
    }

    public entry fun sync (sender: &signer, tokenId: u256, did: String, receiver: vector<u8>, signature: vector<u8>, dstChainId: u64, fee: u64) acquires State {
        let state = borrow_global_mut<State>(@hashkey);
        let sender_address = signer::address_of(sender);
        assert!(*simple_map::borrow(&state.didToTokenId, &did) == tokenId, ERROR_INVALID_ARGUMENT);
        assert!(*simple_map::borrow(&state.ownerOf, &tokenId) == sender_address, ERROR_NOT_OWNER);
        //check signature
        let message = vector::empty<u8>();
        vector::append(&mut message, bcs::to_bytes<address>(&sender_address));
        vector::append(&mut message, bcs::to_bytes<String>(&did));
        vector::append(&mut message, bcs::to_bytes<u256>(&tokenId));
        vector::append(&mut message, receiver);
        let msg_hash = aptos_hash::keccak256(copy message);
        assert!(verify_eth_sig(signature, ETH_SIGNER_ADDRESS, msg_hash), ERROR_INVALID_SIGNATURE);
        
        //transfer gas fee
        let adminer = account::create_signer_with_capability(&state.resource_cap);
        let admin_address = account::create_resource_address(&@hashkey, HASHKEY_SEED);
        coin::register<AptosCoin>(&adminer);
        let fee_in_coin = coin::withdraw<AptosCoin>(sender, fee);
        coin::deposit(admin_address, fee_in_coin);

        event::emit_event<SendEvent>(
            &mut state.send_events,
            SendEvent{
                sender: sender_address,
                dst_chain_id: dstChainId,
                receiver: receiver,
                token_id: tokenId,
                did: did,
                timestamp: timestamp::now_seconds()
        });
    }

    public entry fun withdrawFee(sender: &signer, fee: u64) acquires State {
        let state = borrow_global_mut<State>(@hashkey);
        assert!(signer::address_of(sender) == state.owner_addr, ERROR_NOT_OWNER);
        let adminer = account::create_signer_with_capability(&state.resource_cap);
        coin::register<AptosCoin>(sender);
        let fee_in_coin = coin::withdraw<AptosCoin>(&adminer, fee);
        coin::deposit(signer::address_of(sender), fee_in_coin);
    }

    #[view]
    public fun get_token_id(did: string::String): u256 acquires State {
        let state = borrow_global_mut<State>(@hashkey);
        let tokenId = simple_map::borrow(&state.didToTokenId, &did);
        *tokenId
    }

    #[view]
    public fun get_did(tokenId: u256): String acquires State {
        let state = borrow_global_mut<State>(@hashkey);
        let did = simple_map::borrow(&state.tokenIdToDid, &tokenId);
        *did
    }

    fun mint_internal(receiver_addr: address, did: string::String, tokenId: u256) acquires State {
        let state = borrow_global_mut<State>(@hashkey);
        assert!(!simple_map::contains_key(&state.didClaimed, &did), ERROR_DID_CLAIMED);
        assert!(!simple_map::contains_key(&state.addrClaimed, &receiver_addr), ERROR_ADDR_CLAIMED);

        let adminer = account::create_signer_with_capability(&state.resource_cap);
        //let admin_address = account::create_resource_address(&@hashkey, HASHKEY_SEED);
        let uri = string::utf8(b"https://hashkey.4everland.store/metadata/");
        //let creation_number = account::get_guid_next_creation_num(admin_address);
        aptos_token::mint_soul_bound(
          &adminer,
          string::utf8(b"Hashkey DID"),
          string::utf8(b"Kindle your Web3 highlights and achievements on-chain."),
          std::string_utils::format1(&b"Hashkey #{}", tokenId),
          std::string_utils::format1(&b"https://hashkey.4everland.store/metadata/{}", tokenId),
          vector::empty<String>(),
          vector::empty<String>(),
          vector::empty<vector<u8>>(),
          receiver_addr
        );

        simple_map::add(&mut state.addrClaimed, receiver_addr, true);
        simple_map::add(&mut state.didClaimed, did, true);
        simple_map::add(&mut state.tokenIdToDid, tokenId, did);
        simple_map::add(&mut state.didToTokenId, did, tokenId);
        simple_map::add(&mut state.ownerOf, tokenId, receiver_addr);
        event::emit_event<MintEvent>(
            &mut state.mint_events,
            MintEvent{
                owner: receiver_addr,
                token_id: tokenId,
                uri: uri,
                timestamp: timestamp::now_seconds()
        });
    }

    public fun verifyDIDFormat(_did: vector<u8>): bool {
        if(vector::length(&_did) < 5 || vector::length(&_did) > 54){
            return false
        };
        let i = 0;
        while(i < vector::length(&_did) - 4){
            let c = vector::borrow(&_did, i);
            if (((*c < 48) || (*c > 122)) || ((*c > 57) && (*c < 97))) {
                return false
            };
            i = i + 1;
        };
        if(
            (*vector::borrow(&_did, vector::length(&_did) - 4) != 46) ||
            (*vector::borrow(&_did, vector::length(&_did) - 3) != 107) ||
            (*vector::borrow(&_did, vector::length(&_did) - 2) != 101) ||
            (*vector::borrow(&_did, vector::length(&_did) - 1) != 121)
        ) {
            return false
        };
        return true
    }

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