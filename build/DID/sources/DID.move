module hashkey::DID{

    use std::signer;
    use std::vector;
    use std::signer::address_of;
    use std::string::{Self, String};

    use aptos_std::table::{Self, Table};

    use aptos_token::token;
    use aptos_token::token::{TokenDataId};

    use aptos_framework::account;
    use aptos_framework::account::{SignerCapability, create_resource_account};

    use hashkey::eth_sig_verifier;

    const ENOT_ADMIN_PRIORITY: u64 = 0;
    const EINVALID_PROOF_OF_KNOWLEDGE: u64 = 1;

    struct DGIssuerStorage has key, store {
        owner: address,
        minter_cap: SignerCapability,
        dgIssuer: Table<DeedGrain,address>,
        evidenceUsed: Table<vector<u8>, bool>,
    }

    struct DeedGrain has key, store, copy, drop {
        minted: u64,
        issuer: address,
        transferable: bool,
        token_data_id: TokenDataId,
    }

    fun init_module(sender:&signer) {
        let (resource_signer,resource_signer_cap) = create_resource_account(sender, b"");
        token::create_collection(
            &resource_signer,
            string::utf8(b"DeedGrain"),
            string::utf8(b"Kindle your Web3 highlights and achievements on-chain."), 
            string::utf8(b"https://hashkey.4everland.store/metadata/0"),
            0,
            vector<bool>[true,true,true]
        );
        move_to(sender, DGIssuerStorage {
            owner: signer::address_of(sender),
            minter_cap: resource_signer_cap,
            dgIssuer: table::new(),
            evidenceUsed: table::new(),
        });
    }

    public entry fun issueDG(sender:&signer, baseuri: String, tokenName: String, description: String, evidence: vector<u8>, maximum: u64, addr: vector<u8>, message: vector<u8>) acquires DGIssuerStorage {
        let issuer_addr = signer::address_of(sender);
        let storage = borrow_global_mut<DGIssuerStorage>(@hashkey);
        assert!(eth_sig_verifier::verify_eth_sig(evidence, addr, message), EINVALID_PROOF_OF_KNOWLEDGE);
        // mint token to the receiver
        let resource_signer = account::create_signer_with_capability(&storage.minter_cap);
        let royalty_points_denominator = 1;
        let royalty_points_numerator = 0;
        let token_data_id = token::create_tokendata(
            &resource_signer,
            string::utf8(b"DeedGrain"),
            tokenName,
            description,
            maximum,
            baseuri,
            issuer_addr,
            royalty_points_denominator,
            royalty_points_numerator,
            // we don't allow any mutation to the token
            token::create_token_mutability_config(
                &vector<bool>[ false, false, false, false, true ]
            ),
            vector::empty<string::String>(),
            vector::empty<vector<u8>>(),
            vector::empty<string::String>(),
        );
        let amount = 1;
        let token_id = token::mint_token(&resource_signer, token_data_id, amount);
        token::direct_transfer(&resource_signer, sender, token_id, amount);

        // mutate the token properties to update the property version of this token
        let (creator_address, collection, name) = token::get_token_data_id_fields(&token_data_id);
        token::mutate_token_properties(
            &resource_signer,
            address_of(sender),
            creator_address,
            collection,
            name,
            0,
            1,
            vector::empty<string::String>(),
            vector::empty<vector<u8>>(),
            vector::empty<string::String>(),
        );
        move_to(sender, DeedGrain {
            minted: 1,
            issuer: issuer_addr,
            transferable: true,
            token_data_id: token_data_id,
        });
    }

    public entry fun mintDG(user: &signer, evidence: vector<u8>, addr : vector<u8>, message: vector<u8>) acquires DeedGrain,DGIssuerStorage {
        let user_addr = signer::address_of(user);
        let storage = borrow_global_mut<DGIssuerStorage>(@hashkey);
        let deedgrain = borrow_global_mut<DeedGrain>(user_addr);
        let token_data_id = deedgrain.token_data_id;
        assert!(eth_sig_verifier::verify_eth_sig(evidence, addr, message), EINVALID_PROOF_OF_KNOWLEDGE);

        token::opt_in_direct_transfer(user, true);
        let resource_signer = account::create_signer_with_capability(&storage.minter_cap);
        // Mint the NFT to the buyer account
        token::mint_token_to(&resource_signer, user_addr, token_data_id, 1);
        deedgrain.minted = deedgrain.minted + 1
    }
    
    fun num_str(num: u64): String{
        let v1 = vector::empty();
        while (num/10 > 0){
            let rem = num%10;
            vector::push_back(&mut v1, (rem+48 as u8));
            num = num/10;
        };
        vector::push_back(&mut v1, (num+48 as u8));
        vector::reverse(&mut v1);
        string::utf8(v1)
    }

    fun assert_admin_signer(sign: &signer) {
        assert!(signer::address_of(sign) == @hashkey, ENOT_ADMIN_PRIORITY); 
    }
}