//
//  File.swift
//
//
//  Created by CW Lee on 10/01/2024.
//

import Foundation
import tkey_mpc_swift

import CustomAuth
import TorusUtils
import FetchNodeDetails
import CommonSources


import curveSecp256k1

public struct MpcSigningKit  {
    
    internal var selectedTag: String?;
    internal var factorKey: String?;
    
    internal var oauthKey: String?;
    internal var network: TorusNetwork;
    internal var option: CoreKitOptions;
    internal var state : CoreKitState;
    
    public var metadataHostUrl : String;
    
    public var tkey : ThresholdKey?;
    
    public var tssEndpoints: [String]?;
    public var authSigs: [String]?;
    public var verifier: String?;
    public var verifierId: String?;
    
    public var torusUtils: TorusUtils;
    public var nodeIndexes: [Int]?;
    public var nodeDetails : AllNodeDetailsModel? ;
    
    public var nodeDetailsManager : NodeDetailManager;
    
    public var sigs: [String]?;
    
    
    // init
    public init( web3AuthClientId : String , web3AuthNetwork: TorusNetwork ) {
        self.option = .init(disableHashFactor: false , Web3AuthClientId: web3AuthClientId, network: web3AuthNetwork)
        self.state = CoreKitState.init()
        
        self.network = web3AuthNetwork
        
        self.torusUtils = TorusUtils( enableOneKey: true,
                                     network: self.network )
        
        
        self.nodeDetailsManager = NodeDetailManager(network: self.network)
        
        // will be overwrritten
        self.metadataHostUrl = "https://metadata.tor.us"
    }
    
    public func getDeviceMetadataShareIndex() throws -> String {
        guard let shareIndex = self.state.deviceMetadataShareIndex else {
            throw "share index not found"
        }
        return shareIndex
    }
    
    public mutating func login (loginProvider: LoginProviders, verifier: String ) async throws -> KeyDetails {
        let sub = SubVerifierDetails( loginType: .web,
                                      loginProvider: loginProvider,
                                      clientId: self.option.Web3AuthClientId,
                                      verifier: verifier,
                                      redirectURL: "tdsdk://tdsdk/oauthCallback",
                                      browserRedirectURL: "https://scripts.toruswallet.io/redirect.html"
                                     )
        let customAuth = CustomAuth( aggregateVerifierType: .singleLogin, aggregateVerifier: verifier, subVerifierDetails: [sub], network: self.network, enableOneKey: true)
        
        let userData = try await customAuth.triggerLogin()
        return try await self.login(userData: userData)
    }
    
//    public mutating func loginWithJwt( params: IdTokenLoginParams  ) async throws {
//        let verifier = self.customAuth.aggregateVerifier
//        
//        
//        let torusKey = try await customAuth.getTorusKey(verifier: params.verifier, verifierId: params.verifierId, idToken: params.idToken)
//        let torusKeyData =  TorusKeyData.init(torusKey: torusKey, userInfo: [:])

//        return try await self.login(userData: torusKeyData)
//    }
    
    
    
    // login should return key_details
    // with factor key if new user
    // with required factor > 0 if existing user
    private mutating func login (userData: TorusKeyData) async throws -> KeyDetails {
        
        self.oauthKey = userData.torusKey.oAuthKeyData?.privKey

        guard let verifierLocal = userData.userInfo["verifier"] as? String, let verifierIdLocal = userData.userInfo["verifierId"] as? String else {
            throw ("Error: invalid verifer, verifierId")
        }
        
        self.verifier = verifierLocal;
        self.verifierId = verifierIdLocal;
        
        // get from service provider/ torusUtils
        self.nodeIndexes = []
        
        let fnd = self.nodeDetailsManager
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifierLocal, verifierID: verifierIdLocal)
        
        guard let host = nodeDetails.getTorusNodeEndpoints().first else {
            throw "Invalid node"
        }
        guard let metadatahost = URL( string: host)?.host else {
            throw "invalid metadata endpoint"
        }
        
        let metadataEndpoint = "https://" + metadatahost + "/metadata"

        self.nodeDetails = nodeDetails
        
        self.tssEndpoints = nodeDetails.torusNodeTSSEndpoints
        
        guard let postboxkey = self.oauthKey else {
            throw RuntimeError("error, invalid postboxkey")
        }
        
        guard let sessionData = userData.torusKey.sessionData else {
            throw RuntimeError("error, invalid session data")
        }
        
        let sessionTokenData = sessionData.sessionTokenData

        let signatures = sessionTokenData.map { token in
            return [  "data": Data(hex: token!.token).base64EncodedString(),
                      "sig": token!.signature ]
        }
        
        let sigs: [String] = try signatures.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }
        
        self.authSigs = sigs
        
        // create tkey
        let storage_layer = try StorageLayer(enable_logging: true, host_url: metadataEndpoint, server_time_offset: 2)
        
        let service_provider = try ServiceProvider(enable_logging: true, postbox_key: postboxkey, useTss: true, verifier: verifier, verifierId: verifierId, nodeDetails: nodeDetails)
        
        let rss_comm = try RssComm()
        let thresholdKey = try ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false,
            rss_comm: rss_comm)

        let key_details = try await thresholdKey.initialize(never_initialize_new_key: false, include_local_metadata_transitions: false)

        self.tkey = thresholdKey
        
        if key_details.required_shares > 0 {
            try await self.existingUser()
        } else {
            try await self.newUser()
        }
        
        // to modify to corekit details
        return try thresholdKey.get_key_details()
    }
    
    private mutating func existingUser() async throws {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        
        // try check for hash factor
        if ( self.option.disableHashFactor == false) {
            let factorKey = try self.getHashKey()

            // input hash factor
            do {
                try await self.inputFactor(factorKey: factorKey)
                let _ = try await threshold_key.reconstruct()
            } catch {
                // unable to recover via hashFactor
            }
        }
    }
    
    private mutating func newUser () async throws {
        guard let tkey = self.tkey else {
            throw "Invalid tkey"
        }
        guard let nodeDetails = self.nodeDetails else {
            throw "absent nodeDetails"
        }
        
        let _ = try await tkey.reconstruct()

        // TSS Module Initialize - create default tag
        // generate factor key or use oauthkey hash as factor
        let factorKey :  String
        let descriptionTypeModule : FactorDescriptionTypeModule
        if ( self.option.disableHashFactor == false ) {
            factorKey = try self.getHashKey()
            descriptionTypeModule = FactorDescriptionTypeModule.HashedShare
            
        } else  {
            // random generate
            factorKey  = try curveSecp256k1.SecretKey().serialize()
            descriptionTypeModule = FactorDescriptionTypeModule.DeviceShare
        }
        
        // derive factor pub
        let factorPub = try curveSecp256k1.SecretKey(hex: factorKey).toPublic().serialize(compressed: false)

        // use input to create tag tss share
        let tssIndex = TssShareType.DEVICE
        
        let defaultTag = "default"
        try await TssModule.create_tagged_tss_share(threshold_key: tkey, tss_tag: defaultTag, deviceTssShare: nil, factorPub: factorPub, deviceTssIndex: tssIndex.toInt32(), nodeDetails: nodeDetails, torusUtils: self.torusUtils)

        // backup metadata share using factorKey
        // finding device share index
        var shareIndexes = try tkey.get_shares_indexes()
        shareIndexes.removeAll(where: {$0 == "1"})

        try TssModule.backup_share_with_factor_key(threshold_key: tkey, shareIndex: shareIndexes[0], factorKey: factorKey)
        
        // record share description
        let description = createCoreKitFactorDescription(module: FactorDescriptionTypeModule.HashedShare, tssIndex: tssIndex)
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        try await tkey.add_share_description(key: factorPub, description: jsonStr )

        self.factorKey = factorKey;
    }

    public mutating func inputFactor (factorKey: String) async throws {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        // input factor
        try await threshold_key.input_factor_key(factorKey: factorKey)
        
        // try using better methods ?
        self.state.deviceMetadataShareIndex = try await  TssModule.find_device_share_index(threshold_key: threshold_key, factor_key: factorKey)
        // setup tkey ( assuming only 2 factor is required)
        let _ = try await threshold_key.reconstruct()
        
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        let _ = try await TssModule.get_tss_share(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey)
        self.factorKey = factorKey
    }
    
    
    public func publicKey() async throws -> String {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
       
        return try await TssModule.get_tss_pub_key(threshold_key: threshold_key, tss_tag: selectedTag)
    }
    
    // To remove reset account function
    public func resetAccount () async throws {
        guard let postboxkey = self.oauthKey else {
            throw "Not yet login via oauth"
        }
        let temp_storage_layer = try StorageLayer(enable_logging: true, host_url: self.metadataHostUrl, server_time_offset: 2)
        let temp_service_provider = try ServiceProvider(enable_logging: true, postbox_key: postboxkey)
        let temp_threshold_key = try ThresholdKey(
            storage_layer: temp_storage_layer,
            service_provider: temp_service_provider,
            enable_logging: true,
            manual_sync: false)

        try await temp_threshold_key.storage_layer_set_metadata(private_key: postboxkey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")

//        resetAppState() // Allow reinitialize
    }

    private func getHashKey () throws -> String {
//        export const getHashedPrivateKey = (postboxKey: string, clientId: string): BN => {
//          const uid = `${postboxKey}_${clientId}`;
//          let hashUid = keccak256(Buffer.from(uid, "utf8"));
//          hashUid = hashUid.replace("0x", "");
//          return new BN(hashUid, "hex");
//        };
        guard let oauthKey = self.oauthKey else {
            throw "invalid oauth key"
        }
        guard let uid = "\(oauthKey)_\(self.option.Web3AuthClientId)".data(using: .utf8)?.sha256() else {
            throw "invalid string in getHashKey"
        }
        
        return try curveSecp256k1.SecretKey(hex: uid.hexString).serialize()
    }
    
    
// retrieve from keychain
//        guard let factorPub = UserDefaults.standard.string(forKey: metadataPublicKey ) else {
//             alertContent = "Failed to find device share."
//             showAlert = true
//             showSpinner = SpinnerLocation.nowhere
//             showRecovery = true
//             return
//         }

        
//            deviceFactorPub = factorPub
//            let factorKey = try KeychainInterface.fetch(key: factorPub)
//            try await threshold_key.input_factor_key(factorKey: factorKey)
//            let pk = PrivateKey(hex: factorKey)
//            deviceFactorPub = try pk.toPublic()
    
    
    
// Save to keychain
    
    // point metadata pubkey to factorPub
//    UserDefaults.standard.set(factorPub, forKey: metadataPublicKey)

    // can be moved
    // save factor key in keychain using factorPub ( this factor key should be saved in any where that is accessable by the device)
//    guard let _ = try? KeychainInterface.save(item: factorKey.hex, key: factorPub) else {
//        throw "Failed to save factor key"
//    }
    
    
//    let defaultTssShareDescription = try thresholdKey.get_share_descriptions()
//    metadataDescription = "\(defaultTssShareDescription)"
}


