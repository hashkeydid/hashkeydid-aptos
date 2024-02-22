module hashkey::DID {
    use std::signer;
    use std::vector;
    use std::string::{Self, String};

    use aptos_std::from_bcs::to_address;
    use aptos_std::table::{Self, Table};
    use aptos_std::simple_map::{Self, SimpleMap};

    use aptos_token_objects::aptos_token;

    use aptos_framework::account;
    use aptos_framework::timestamp;
    use aptos_framework::coin::Self;
    use aptos_framework::object::{Self};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::event::{Self, EventHandle};
    
    use layerzero::lzapp;
    use layerzero::remote;
    use layerzero_common::serde; 
    use layerzero_common::utils::{vector_slice, assert_length};  
    use layerzero::endpoint::{Self, UaCapability};

    use hashkey::auid_manager::{Self};
    
    ///
    /// Errors
    ///
    const ERROR_NOT_OWNER: u64 = 0;
    const ERROR_DID_CLAIMED: u64 = 1;
    const ERROR_ADDR_CLAIMED: u64 = 2;

    ///
    /// Data structures
    ///
    struct DidUA {}

    struct Capabilities has key {
        cap: UaCapability<DidUA>,
    }

    struct State has key {
        nft_collection: SimpleMap<u32, u64>, // SimpleMap<Did Token id, Aptos NFT Creation Number>
        addrClaimed: Table<address, bool>,
        didClaimed: Table<string::String, bool>,
        minter_cap: account::SignerCapability,
        owner: address,
        mint_events: EventHandle<MintEvent>,
        send_events: EventHandle<SendEvent>,
        recv_events: EventHandle<RecvEvent>,
    }

    /// 
    /// Seed
    /// 
    const HASHKEY_SEED: vector<u8> = b"HashKey";

    //
    // Events
    //
    struct MintEvent has store, drop {
        owner: address,
        token_id: u32,
        uri: String,
        creation_number: u64,
        timestamp: u64
    }

    struct SendEvent has store, drop {
        sender: address,
        dst_chain_id: u64,
        dst_address: vector<u8>,
        receiver: vector<u8>,
        token_id: u32,
        timestamp: u64
    }

    struct RecvEvent has store, drop {
        src_chain_id: u64,
        src_address: vector<u8>,
        receiver: address,
        token_id: u32,
        timestamp: u64
    }

    //
    // Entry functions
    //
    fun init_module(sender:&signer) {
        let (resource_signer,resource_signer_cap) = account::create_resource_account(sender, HASHKEY_SEED);

        let cap = endpoint::register_ua<DidUA>(sender);
        lzapp::init(sender, cap);
        remote::init(sender);

        move_to(sender, Capabilities { cap });
        
        move_to(sender, State {
            nft_collection: simple_map::create<u32, u64>(),
            addrClaimed: table::new(),
            didClaimed: table::new(),
            minter_cap: resource_signer_cap,
            owner: signer::address_of(sender),
            mint_events: account::new_event_handle<MintEvent>(&resource_signer),
            send_events: account::new_event_handle<SendEvent>(&resource_signer),
            recv_events: account::new_event_handle<RecvEvent>(&resource_signer),
        });

        aptos_token::create_collection(
            &resource_signer,
            string::utf8(b"Kindle your Web3 highlights and achievements on-chain."),
            0,
            string::utf8(b"Hashkey DID"), 
            string::utf8(b"https://hashkey.4everland.store/metadata/0"),
            false,  // mutable_description
            false,  // mutable_royalty
            false,  // mutable_uri
            false,  // mutable_token_description
            false,  // mutable_token_name
            false,  // mutable_token_properties
            false,  // mutable_token_uri
            false,  // tokens_burnable_by_creator
            true,  // tokens_freezable_by_creator
            1,  // royalty_numerator
            10,  // royalty_denominator
        );
    }

    public entry fun mintDid(receiver: &signer, did: string::String, tokenId: u32) acquires State {
        let receiver_addr = signer::address_of(receiver);
        let state = borrow_global_mut<State>(@hashkey);
        assert!(table::contains(&state.didClaimed, did), ERROR_DID_CLAIMED);
        assert!(table::contains(&state.addrClaimed, receiver_addr), ERROR_ADDR_CLAIMED);
        let adminer = account::create_signer_with_capability(&state.minter_cap);
        let auids = auid_manager::create();
        let admin_address = account::create_resource_address(&@hashkey, HASHKEY_SEED);
        let uri = string::utf8(b"https://hashkey.4everland.store/metadata/");
        let creation_number = account::get_guid_next_creation_num(admin_address);
        aptos_token::mint(
          &adminer,
          string::utf8(b"Hashkey DID"),
          string::utf8(b"Kindle your Web3 highlights and achievements on-chain."),
          std::string_utils::format2(&b"Hashkey #{} #{}", tokenId, creation_number),
          uri,
          vector::empty<String>(),
          vector::empty<String>(),
          vector::empty<vector<u8>>()
        );

        table::add(&mut state.addrClaimed, receiver_addr, true);
        table::add(&mut state.didClaimed, did, true);

        let token_address = auid_manager::increment(&mut auids);

        let token_obj = object::address_to_object<aptos_token::AptosToken>(token_address);
        
        object::transfer(&adminer, token_obj, receiver_addr);

        simple_map::add(&mut state.nft_collection, tokenId, creation_number);

        auid_manager::destroy(auids);

        event::emit_event<MintEvent>(
            &mut state.mint_events,
            MintEvent{
                owner: signer::address_of(receiver),
                token_id: tokenId,
                uri: uri,
                creation_number: creation_number,
                timestamp: timestamp::now_seconds()
        });
    }

    public entry fun send(
        sender: &signer,          // ONFT owner
        dstChainId: u64,        // dst Chain ID
        // dst_address: vector<u8>, // dst UA address
        dst_receiver: vector<u8>,  // ONFT receiver
        fee: u64,               // fee to send
        tokenId: u32            // ONFT token ID to send
    ) acquires State, Capabilities {

        let admin_address = account::create_resource_address(&@hashkey, HASHKEY_SEED);
        // send to lzendpoint
        let fee_in_coin = coin::withdraw<AptosCoin>(sender, fee);
        let sender_address = signer::address_of(sender);
        
        let state = borrow_global_mut<State>(@hashkey);
        let cap = borrow_global<Capabilities>(@hashkey);

        let _adminer = account::create_signer_with_capability(&state.minter_cap);
        let dst_address = remote::get(@hashkey, dstChainId);
        let payload = encode_send_payload(dst_receiver, tokenId);
        let (_, refund) = lzapp::send<DidUA>(dstChainId, dst_address, payload, fee_in_coin, vector::empty<u8>(), vector::empty<u8>(), &cap.cap);
        // send nft here
        let creation_number = simple_map::borrow(&state.nft_collection, &tokenId);
        let token_address = object::create_guid_object_address(admin_address, *creation_number);
        let token_obj = object::address_to_object<aptos_token::AptosToken>(token_address);
        assert!(object::owner(token_obj) == sender_address, 199999);

        // object::transfer(sender, token_obj, admin_address);
        object::transfer_raw(sender, token_address, admin_address);
        // aptos_token::freeze_transfer(&adminer,token_obj );
        // deposit refunds
        coin::deposit(sender_address, refund);

        event::emit_event<SendEvent>(
            &mut state.send_events,
            SendEvent{
                sender: signer::address_of(sender),
                dst_chain_id: dstChainId,
                dst_address: dst_address,
                receiver: dst_receiver,
                token_id: tokenId,
                timestamp: timestamp::now_seconds()           
        });
    }

    // receive nft 
    public entry fun lz_receive(chain_id: u64, src_address: vector<u8>, payload: vector<u8>) acquires State, Capabilities {
        lz_receive_internal(chain_id, src_address, payload);
    }
    
    public fun quote_fee(dst_chain_id: u64, pay_in_zro: bool, adapter_params: vector<u8>, msglib_params: vector<u8>): (u64, u64) {
        endpoint::quote_fee(@hashkey, dst_chain_id, 64, pay_in_zro, adapter_params, msglib_params)
    }

    // internal function

    inline fun assert_admin_signer(sign: &signer) {
        assert!(signer::address_of(sign) == @hashkey, ERROR_NOT_OWNER); 
    }

    fun lz_receive_internal(
        src_chain_id: u64, 
        src_address: vector<u8>, 
        payload: vector<u8>
    ) : (u32) acquires State, Capabilities {
        let admin_address = account::create_resource_address(&@hashkey, HASHKEY_SEED);

        remote::assert_remote(@hashkey, src_chain_id, src_address);
        let cap = borrow_global<Capabilities>(@hashkey);
        endpoint::lz_receive<DidUA>(src_chain_id, src_address, payload, &cap.cap);

        // get receiver address and tokenId from payload
        let (receiver_address, tokenId) = decode_receive_payload(&payload);

        // if tokenId exists send to receiver or if not mint tokenId
        let state = borrow_global_mut<State>(@hashkey);
        let adminer = account::create_signer_with_capability(&state.minter_cap);

        event::emit_event<RecvEvent>(
            &mut state.recv_events,
            RecvEvent {
                src_chain_id,
                src_address,
                receiver: receiver_address,
                token_id: tokenId,
                timestamp: timestamp::now_seconds()                
        });
        
        if (simple_map::contains_key(&state.nft_collection, &tokenId)) {
            let creation_number = simple_map::borrow(&state.nft_collection, &tokenId);
            let token_address = object::create_guid_object_address(admin_address, *creation_number);
            let _token_obj = object::address_to_object<aptos_token::AptosToken>(token_address);
            // object::transfer(&adminer, token_obj, (receiver_address));
            object::transfer_raw(&adminer, token_address, (receiver_address));
        } else {
            //mint_nft((receiver_address), string::utf8(b"Hashkey Did"), string::utf8(b"Hashkey ONFT"));
        };

        (tokenId)
    }

    // encode send payload : receiver_address(32) + tokenId(4)
    fun encode_send_payload(
        dst_receiver: vector<u8>,
        tokenId: u32
    ): vector<u8> {
        // assert_length(&dst_receiver, 32);

        let payload = vector::empty<u8>();
        serde::serialize_vector(&mut payload, dst_receiver);
        serde::serialize_u16(&mut payload, (((tokenId >> 16) & 0xFFFF) as u64));
        serde::serialize_u16(&mut payload, ((tokenId) as u64));

        // assert_length(&payload, 36);

        payload
    }

    // decode received payload : receiver_address(32) + tokenId(4)
    fun decode_receive_payload(payload: &vector<u8>): (address, u32) {
        assert_length(payload, 36);

        let receiver_address = to_address(vector_slice(payload, 0, 32));
        let tokenId1 = serde::deserialize_u16(&vector_slice(payload, 32, 34));
        let tokenId2 = serde::deserialize_u16(&vector_slice(payload, 34, 36));

        (receiver_address, ((tokenId2 | tokenId1 << 16) as u32))
    }
}