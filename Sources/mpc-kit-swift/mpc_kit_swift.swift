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

    public var tkey : ThresholdKey?;
    public var customAuth: CustomAuth;
    
    
    public var selectedTag: String?;
    public var tssEndpoints: [String]?;
    public var authSigs: [String]?;
    public var verifier: String?;
    public var verifierId: String?;
    public var factorKey: String?;
//    public var tssNonce: Int32;
    
    public var nodeIndexes: [Int]?;
    
    public var publicKey: String?;
    
    public var torusUtils: TorusUtils;
    public var nodeDetails : AllNodeDetailsModel? ;
    
    public var nodeDetailsManager : NodeDetailManager;
    
    public var sigs: [String]?;
    
    private var oauthKey: String?;
    
    private var network: TorusNetwork;
    
    private var option: CoreKitOptions;
    
    private var metadataHostUrl : String;
    
    // init
    public init() {
        self.option = .init(disableHashFactor: true , Web3AuthClientId: "clientIdtesting")
        
        
        self.network = .sapphire(.SAPPHIRE_DEVNET)
        
        self.torusUtils = TorusUtils( enableOneKey: true,
                                     network: self.network )
        
        let sub = SubVerifierDetails(loginType: .web,
                                     loginProvider: .google,
                                     clientId: "221898609709-obfn3p63741l5333093430j3qeiinaa8.apps.googleusercontent.com",
                                     verifier: "google-lrc",
                                     redirectURL: "tdsdk://tdsdk/oauthCallback",
                                     browserRedirectURL: "https://scripts.toruswallet.io/redirect.html"
                                     )
        
        self.customAuth = CustomAuth( aggregateVerifierType: .singleLogin, aggregateVerifier: "google-lrc", subVerifierDetails: [sub], network: self.network, enableOneKey: true)
        
        self.nodeDetailsManager = NodeDetailManager(network: self.network)
        
        // will be overwrritten
        self.metadataHostUrl = "https://metadata.tor.us"
        
    }
    
    
    public mutating func login () async throws {
        let userData = try await customAuth.triggerLogin()
        return try await self.login(userData: userData)
    }
    
    public mutating func loginWithJwt( params: IdTokenLoginParams  ) async throws {
        
        let verifier = self.customAuth.aggregateVerifier
        
        
        let torusKey = try await customAuth.getTorusKey(verifier: params.verifier, verifierId: params.verifierId, idToken: params.idToken)
//        let torusKeyData =  TorusKeyData.init(torusKey: torusKey, userInfo: [:])

//        return try await self.login(userData: torusKeyData)
    }
    
    
    
    // login should return key_details
    // with factor key if new user
    // with required factor > 0 if existing user
    private mutating func login (userData: TorusKeyData) async throws {
        
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
        
//        self.metadataHostUrl = nodeDetails.getTorusNodeEndpoints()[0] + "/metadata/jrpc"

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
        let storage_layer = try StorageLayer(enable_logging: true, host_url: self.metadataHostUrl, server_time_offset: 2)
        
//        let tssEndpoint = nodeDetails.torusNodeTSSEndpoints
//        self.tssEndpoints = tssEndpoint
        
        let service_provider = try ServiceProvider(enable_logging: true, postbox_key: postboxkey, useTss: true, verifier: verifier, verifierId: verifierId, nodeDetails: nodeDetails)
        
        let rss_comm = try RssComm()
        let thresholdKey = try ThresholdKey(
            storage_layer: storage_layer,
            service_provider: service_provider,
            enable_logging: true,
            manual_sync: false,
            rss_comm: rss_comm)

        let key_details = try await thresholdKey.initialize(never_initialize_new_key: false, include_local_metadata_transitions: false)

        print(key_details.total_shares)
        print(key_details.required_shares)
        print(key_details.pub_key)
        let totalShares = Int(key_details.total_shares)
        let threshold = Int(key_details.threshold)
        let tkeyInitalized = true
        
        // public key of the metadatakey
//        let metadataPublicKey = try key_details.pub_key.getPublicKey(format: .EllipticCompress)
        
        self.tkey = thresholdKey
        
        if key_details.required_shares > 0 {
            return try await self.existingUser()
        } else {
            return try await self.newUser()
        }
        
    }
    
    private func existingUser() async throws {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        
        // exising user
        // TODO HERE CONTINUE
        // MANAGED TO LOGIN VIA OAUTH
        // TRY RECOVER USING OAUTH HASH FACTOR -> RECONSTRUCT
        
        // HANDLE FOR NOT ENOUGH SHARE
        
        // try check for hash factor
        if ( self.option.disableHashFactor == false) {
            let factorKey = self.getHashKey()
            
            
            // input hash factor
            // update state
            
            
            //        let allTags = try threshold_key.get_all_tss_tags()
            let tag = "default" // allTags[0]
            let reconstructionDetails = try await threshold_key.reconstruct()
            
            //        let metadataKey = reconstructionDetails.key
            //        let tkeyReconstructed = true
            //        let resetAccount = false
        } else {
            // return key_details
            
        }
        // check if default in all tags else ??
//        let tssPublicKey = try await TssModule.get_tss_pub_key(threshold_key: threshold_key, tss_tag: tag )

//        let defaultTssShareDescription = try threshold_key.get_share_descriptions()

        
        // else return keyDetails
        
//        let metadataDescription = "\(defaultTssShareDescription)"
//        print(defaultTssShareDescription)
    }
    
    private mutating func newUser () async throws {
        guard let tkey = self.tkey else {
            throw "Invalid tkey"
        }
        
        guard (try? await tkey.reconstruct()) != nil else {
            throw "unable to recontruct tkey"
        }

        // TSS Module Initialize - create default tag
        // generate factor key or use oauthkey hash as factor
        let factorKey :  String
        if ( self.option.disableHashFactor == false ) {
            factorKey = self.getHashKey()
        } else  {
            // random generate
            factorKey  = try curveSecp256k1.SecretKey().serialize()
        }
        
        // derive factor pub
        let factorPub = try curveSecp256k1.SecretKey(hex: factorKey).toPublic().serialize(compressed: false)

        // use input to create tag tss share
        let tssIndex = Int32(2)
        
        let defaultTag = "default"
        try await TssModule.create_tagged_tss_share(threshold_key: tkey, tss_tag: defaultTag, deviceTssShare: nil, factorPub: factorPub, deviceTssIndex: tssIndex, nodeDetails: self.nodeDetails!, torusUtils: self.torusUtils)

//        let tssPublicKey = try await TssModule.get_tss_pub_key(threshold_key: tkey, tss_tag: defaultTag)

        // finding device share index
        var shareIndexes = try tkey.get_shares_indexes()
        shareIndexes.removeAll(where: {$0 == "1"})

        // backup metadata share using factorKey
        try TssModule.backup_share_with_factor_key(threshold_key: tkey, shareIndex: shareIndexes[0], factorKey: factorKey)
        
        let description = [
            "module": "Device Factor key",
            "tssTag": defaultTag,
            "tssShareIndex": tssIndex,
            "dateAdded": Date().timeIntervalSince1970
        ] as [String: Codable]
        
        let jsonStr = try factorDescription(dataObj: description)

        try await tkey.add_share_description(key: factorPub, description: jsonStr )

        let reconstructionDetails = try await tkey.reconstruct()

        let metadataKey = reconstructionDetails.key
        let tkeyReconstructed = true
        let resetAccount = false
        
        //
        self.factorKey = factorKey;
        
        let selectedTag = try TssModule.get_tss_tag(threshold_key: tkey)
       
        self.publicKey = try await TssModule.get_tss_pub_key(threshold_key: tkey, tss_tag: selectedTag)
        
        // return key_details
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

    private func getHashKey () -> String {
        return Data(hex: self.oauthKey! + self.option.Web3AuthClientId ).sha512().hexString
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


