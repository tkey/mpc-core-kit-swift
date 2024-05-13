//
//  File.swift
//
//
//  Created by CW Lee on 10/01/2024.
//

import Foundation
import tkey

import CustomAuth
import TorusUtils
import FetchNodeDetails
import SingleFactorAuth



import curveSecp256k1

public struct MpcCoreKit  {
    
    internal var selectedTag: String?;
    internal var factorKey: String?;
    
    internal var oauthKey: String?;
    internal var network: Web3AuthNetwork;
    internal var option: CoreKitOptions;
    
    internal var appState : CoreKitAppState;
    
    public var metadataHostUrl : String?;
    
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
    
    public var coreKitStorage : CoreKitStorage
    
    private let storeKey = "corekitStore"
    
    private let localAppStateKey = "localAppState"
    
    
    // init
    public init( web3AuthClientId : String , web3AuthNetwork: Web3AuthNetwork, disableHashFactor : Bool = false, localStorage: ILocalStorage ) {
        self.option = .init(disableHashFactor: disableHashFactor , Web3AuthClientId: web3AuthClientId, network: web3AuthNetwork)
        self.appState = CoreKitAppState.init()
        
        self.network = web3AuthNetwork
        
        self.torusUtils = TorusUtils( enableOneKey: true,
                                      network: self.network.toTorusNetwork(), clientId: web3AuthClientId )
        
        self.nodeDetailsManager = NodeDetailManager(network: self.network.toTorusNetwork())
        
        self.coreKitStorage = .init(storeKey: self.storeKey, storage: localStorage)

    }
    
//    public mutating func rehydrate() async throws {
//        let appState : CoreKitAppState = try await self.coreKitStorage.get(key: self.localAppStateKey)
    //        _
//    }
    
    public mutating func updateAppState( state: CoreKitAppState) async throws {
        // mutating self
        self.appState.merge(with: state)
        
        let jsonState = try JSONEncoder().encode(self.appState).bytes
        try await self.coreKitStorage.set(key: self.localAppStateKey, payload: jsonState )
    }
    
    public func getCurrentFactorKey() throws -> String {
        guard let factor = self.appState.factorKey else {
            throw "factor key absent"
        }
        return factor
    }
    
    public func getDeviceMetadataShareIndex() throws -> String {
        guard let shareIndex = self.appState.deviceMetadataShareIndex else {
            throw "share index not found"
        }
        return shareIndex
    }
    
    public mutating func loginWithOAuth(loginProvider: LoginProviders, clientId: String, verifier: String , jwtParams: [String: String] = [:], redirectURL: String = "tdsdk://tdsdk/oauthCallback", browserRedirectURL: String = "https://scripts.toruswallet.io/redirect.html" ) async throws -> MpcKeyDetails {
        if loginProvider == .jwt && jwtParams.isEmpty {
            throw "jwt login should provide jwtParams"
        }
        
        let sub = SubVerifierDetails( loginType: .web,
                                      loginProvider: loginProvider,
                                      clientId: clientId,
                                      verifier: verifier,
                                      redirectURL: redirectURL,
                                      browserRedirectURL: browserRedirectURL,
                                      jwtParams: jwtParams
                                     )
        let customAuth = CustomAuth(web3AuthClientId: option.Web3AuthClientId, aggregateVerifierType: .singleLogin, aggregateVerifier: verifier, subVerifierDetails: [sub], network: self.network.toTorusNetwork(), enableOneKey: true)
        
        let userData = try await customAuth.triggerLogin()
        return try await self.login(userData: userData)
    }
    
    
    // mneomonic to share
    public func mnemonicToKey(shareMnemonic: String, format: String) -> String? {
        // Assuming ShareSerializationModule.deserializeMnemonic returns Data
        let factorKey = try? ShareSerializationModule.deserialize_share(threshold_key: tkey!, share: shareMnemonic, format: format);
        return factorKey;
    }

    // share to mneomonic
    public func keyToMnemonic(factorKey: String, format: String) -> String? {
        // Assuming ShareSerializationModule.deserializeMnemonic returns Data
        let mnemonic = try? ShareSerializationModule.serialize_share(threshold_key: tkey!, share: factorKey, format: format)
        return mnemonic
    }
    public mutating func loginWithJwt(verifier: String, verifierId: String, idToken: String , userInfo : [String:Any] = [:] ) async throws -> MpcKeyDetails {
        let singleFactor = SingleFactorAuth(singleFactorAuthArgs: .init( web3AuthClientId: self.option.Web3AuthClientId ,network: self.network))
        
        let torusKey = try await singleFactor.getTorusKey(loginParams: .init(verifier: verifier, verifierId: verifierId, idToken: idToken))
        print(torusKey)
        var modUserInfo = userInfo
        modUserInfo.updateValue(verifier, forKey: "verifier")
        modUserInfo.updateValue(verifierId, forKey: "verifierId")
        return try await self.login(userData: TorusKeyData(torusKey: torusKey, userInfo: modUserInfo))
    }
    
    // login should return key_details
    // with factor key if new user
    // with required factor > 0 if existing user
    private mutating func login (userData: TorusKeyData) async throws -> MpcKeyDetails {
        
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

        
        self.metadataHostUrl = metadataEndpoint
        
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
        
        // initialize tkey
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
        self.appState.metadataPubKey = try key_details.pub_key.getPublicKey(format: .EllipticCompress)
        
        self.tkey = thresholdKey
        
        if key_details.required_shares > 0 {
            try await self.existingUser()
        } else {
            try await self.newUser()
        }
        
        // to add tss pub details to corekit details
        let finalKeyDetails = try thresholdKey.get_key_details()
        let tssTag = try TssModule.get_tss_tag(threshold_key: thresholdKey)
        let tssPubKey = try await TssModule.get_tss_pub_key(threshold_key: thresholdKey, tss_tag: tssTag)
        return .init(tssPubKey: tssPubKey, metadataPubKey: try finalKeyDetails.pub_key.getPublicKey(format: .EllipticCompress), requiredFactors: finalKeyDetails.required_shares, threshold: finalKeyDetails.threshold, shareDescriptions: finalKeyDetails.share_descriptions, total_shares: finalKeyDetails.total_shares)
    }
    
    private mutating func existingUser() async throws {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        
        var factor: String?
        // try check for hash factor
        if ( self.option.disableHashFactor == false) {
            factor = try? self.getHashKey()
            // if factor not found, continue forward and try to retrive device factor
            if factor != nil {
                do {
                    try await self.inputFactor(factorKey: factor!)
                    self.factorKey = factor
                    return
                } catch {
                    // swallow on invalid hashFactor
                }
            }
        }
        
        // try check device Storage
        do {
            factor = try? await self.getDeviceFactor()
            // factor not found, return and request factor from inputFactor function
            guard let factor = factor else {
                print("device Factor not found")
                return
            }
            
            try await self.inputFactor(factorKey: factor)
            self.factorKey = factor
        } catch {
            // swallow on invalid device factor
            // do not throw to allow input factor
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
        let description = createCoreKitFactorDescription(module: descriptionTypeModule, tssIndex: tssIndex)
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        try await tkey.add_share_description(key: factorPub, description: jsonStr )

        self.factorKey = factorKey;
        let deviceMetadataShareIndex = try await  TssModule.find_device_share_index(threshold_key: tkey, factor_key: factorKey)
        
        let metadataPubKey = try tkey.get_key_details().pub_key.getPublicKey(format: .EllipticCompress)
        try await self.updateAppState(state: .init(factorKey: factorKey, metadataPubKey: metadataPubKey, deviceMetadataShareIndex: deviceMetadataShareIndex))
        
        // save as device factor if hashfactor is disable
        if ( self.option.disableHashFactor == true ) {
            try await self.setDeviceFactor(factorKey: factorKey)
        }
    }
    
    public mutating func logout () async throws {
        self.appState = .init()
        let jsonState = try JSONEncoder().encode(self.appState).bytes
        try await self.coreKitStorage.set(key: self.localAppStateKey, payload: jsonState)
    }

    public mutating func inputFactor (factorKey: String) async throws {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        // input factor
        try await threshold_key.input_factor_key(factorKey: factorKey)
        
        // try using better methods ?
        let deviceMetadataShareIndex = try await  TssModule.find_device_share_index(threshold_key: threshold_key, factor_key: factorKey)
        try await self.updateAppState(state: .init(deviceMetadataShareIndex: deviceMetadataShareIndex))
        
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
        
        guard let threshold_key = self.tkey else {
            throw "invalid Tkey"
        }
        
        guard let _ = self.metadataHostUrl else {
            throw "invalid metadata url"
        }
        
        try await threshold_key.storage_layer_set_metadata(private_key: postboxkey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")

        // reset appState
        try await self.resetDeviceFactorStore()
        try await self.coreKitStorage.set(key: self.localAppStateKey, payload: [:])
//        try await self.coreKitStorage.set(key: self.localAppStateKey, payload: [:])
    }

    internal func getHashKey () throws -> String {
        guard let oauthKey = self.oauthKey else {
            throw "invalid oauth key"
        }
        guard let uid = try "\(oauthKey)_\(self.option.Web3AuthClientId)".data(using: .utf8)?.sha3(varient: Variants.KECCAK256 ).toHexString() else {
            throw "invalid string in getHashKey"
        }
        let key = try curveSecp256k1.SecretKey(hex: uid).serialize()
        return key
    }
}
