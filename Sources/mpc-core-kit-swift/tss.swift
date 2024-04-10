//
//  File.swift
//  
//
//  Created by CW Lee on 19/01/2024.
//

import Foundation
import CustomAuth
import TorusUtils
import tss_client_swift
import tkey_mpc_swift
import curveSecp256k1
import BigInt
import UIKit

extension MpcCoreKit {
    
    public func getTssPubKey () async throws -> Data {
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        let result = try await TssModule.get_tss_pub_key(threshold_key: threshold_key, tss_tag: selectedTag)
        return Data(hex: result)
    }
    
    
    public func getTssPubKey () -> Data {
        
        let semaphore = DispatchSemaphore(value: 0)
        var result : Data?
        performAsyncOperation(completion: { myresult  in
            result = myresult
            semaphore.signal()
        })
        semaphore.wait()
        return result ?? Data([])
    }
    
    
    func performAsyncOperation(completion: @escaping (Data) -> Void) {
        Task {
            // Simulate an asynchronous operation
            let result = try await self.getTssPubKey()
            print (result)
            completion(result)
        }
    }
    
    /// Signing Data without hashing
    public func tssSign(message: Data) async throws -> Data {
        guard let authSigs = self.authSigs else {
            throw TSSClientError("Invalid authSigns")
        }
        
        guard let tkey = self.tkey else {
            throw TSSClientError("invalid tkey")
        }
        
        let selectedTag = try TssModule.get_tss_tag(threshold_key: tkey)
        // Create tss Client using helper
        
        let (client, coeffs) = try await self.bootstrapTssClient( selected_tag: selectedTag)

        
        // Wait for sockets to be connected
        let connected = try client.checkConnected()
        if !(connected) {
            throw "Client not connected"
        }

        let precompute = try client.precompute(serverCoeffs: coeffs, signatures: authSigs)
        let ready = try client.isReady()
        if !(ready) {
            throw RuntimeError("Error, client not ready")
        }
        
        let signingMessage = message.base64EncodedString()
        let (s, r, v) = try! client.sign(message: signingMessage, hashOnly: true, original_message: "", precompute: precompute, signatures: authSigs)

        try! client.cleanup(signatures: authSigs)

        return r.magnitude.serialize() + s.magnitude.serialize() + Data([v])
    }
    
    public func tssSign (message: Data) -> Data {
        
        let semaphore = DispatchSemaphore(value: 0)
        var result : Data?
        performAsyncTssSignOperation(message: message, completion: { myresult  in
            result = myresult
            semaphore.signal()
        })
        let _ = semaphore.wait(timeout: .now() + 100_000_000_000)
        
        //gepoubkey
        return result ?? Data([])
    }
    
    func performAsyncTssSignOperation(message:Data,  completion: @escaping (Data) -> Void) {
        Task {
            do {
                // Simulate an asynchronous operation
                let result = try await self.tssSign(message: message )
                completion(result)
            }catch {
                completion(Data())
            }
        }
    }
    
    public func getAllFactorPubs () async throws -> [String] {
        guard let threshold_key = self.tkey else {
            throw "tkey is not available"
        }
        
        let currentTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        return try await TssModule.get_all_factor_pub(threshold_key: threshold_key, tss_tag: currentTag)
    }
    
    
    /// * A BN used for encrypting your Device/ Recovery TSS Key Share. You can generate it using `generateFactorKey()` function or use an existing one.
    ///
    /// factorKey?: BN;
    /// Setting the Description of Share - Security Questions, Device Share, Seed Phrase, Password Share, Social Share, Other. Default is Other.
    ///
    /// shareDescription?: FactorKeyTypeShareDescription;
    ///  * Additional metadata information you want to be stored alongside this factor for easy identification.
    /// additionalMetadata?: Record<string, string>;
    public func createFactor( tssShareIndex: TssShareType, factorKey: String?, factorDescription: FactorDescriptionTypeModule, additionalMetadata: [String: Any] = [:]) async throws -> String {
        // check for index is same as factor key
        guard let threshold_key = self.tkey else {
            throw "Invalid tkey"
        }
        guard let curFactorKey = self.factorKey else {
            throw "invalid current FactorKey"
        }
        
        let newFactor = try factorKey ?? curveSecp256k1.SecretKey().serialize()
        
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        print(selectedTag,"selected tag")
        let (tssIndex, _ ) = try await TssModule.get_tss_share(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: curFactorKey)
        // create new factor if different index
        if ( tssIndex == tssShareIndex.toString()) {
            try await self.copyFactor(newFactorKey: newFactor, tssShareIndex: tssShareIndex)
        } else {
            // copy if same index
            try await self.addNewFactor(newFactorKey: newFactor, tssShareIndex: tssShareIndex)
        }
        
        // backup metadata share using factorKey
        let shareIndex = try self.getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactor)
        
        // update description
        let description = createCoreKitFactorDescription(module: FactorDescriptionTypeModule.HashedShare, tssIndex: tssShareIndex)
        let jsonStr = try factorDescriptionToJsonStr(dataObj: description)
        let factorPub = try curveSecp256k1.SecretKey(hex: newFactor).toPublic().serialize(compressed: true)
        try await threshold_key.add_share_description(key: factorPub, description: jsonStr )
        
        return newFactor
    }
    
    public func deleteFactor ( deleteFactorPub: String, deleteFactorKey: String? = nil) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey, let sigs = self.authSigs else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        
        try await TssModule.delete_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, delete_factor_pub: deleteFactorPub, nodeDetails: nodeDetails!, torusUtils: torusUtils)
        
        // delete backup metadata share with factorkey
        if let deleteFactorKey = deleteFactorKey {
            let factorkey = try curveSecp256k1.SecretKey(hex: deleteFactorKey)
            if try factorkey.toPublic().serialize(compressed: true) != curveSecp256k1.PublicKey(hex: deleteFactorPub).serialize(compressed: true) {
                // unmatch public key
                throw "unmatch factorPub and factor key"
            }
            // set metadata to Not Found
            try await self.tkey?.storage_layer_set_metadata(private_key: deleteFactorKey, json: "{ \"message\": \"KEY_NOT_FOUND\" }")
        }
    }
    
    private func copyFactor ( newFactorKey: String, tssShareIndex: TssShareType ) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)
        
        // backup metadata share with factorkey
        let shareIndex = try self.getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)
        
        try await TssModule.copy_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey, newFactorPub: newFactorPub, tss_index: tssShareIndex.toInt32())
    }
    
    private func addNewFactor ( newFactorKey: String, tssShareIndex: TssShareType ) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey, let sigs = self.authSigs else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)
        
        // backup metadata share with factorkey
        let shareIndex = try self.getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)
        
        try await TssModule.add_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, new_factor_pub: newFactorPub, new_tss_index: tssShareIndex.toInt32(), nodeDetails: nodeDetails!, torusUtils: torusUtils)
    }
    
    public mutating func enableMFA ( enableMFA : enableMFARecoveryFactor = .init(), recoveryFactor : Bool = true ) async throws -> String? {
//        self.checkHashFactor()
        guard let metadataPubKey = self.appState.metadataPubKey else {
            throw "invalid metadataPubKey"
        }
        let full = try curveSecp256k1.PublicKey(hex: metadataPubKey).serialize(compressed: false)
        let xCordinate = String(full.suffix(128).prefix(64))
        
        let hashFactorKey = try self.getHashKey()
        
        let additionalDeviceMetadata = await [
            "device" : UIDevice.current.model,
            "name" : UIDevice.current.name
        ]
        let deviceFactor = try await self.createFactor(tssShareIndex: .DEVICE, factorKey: nil, factorDescription: .DeviceShare, additionalMetadata: additionalDeviceMetadata)
        
        // store to device
        try await self.setDeviceFactor(factorKey: deviceFactor)
        try await self.inputFactor(factorKey: deviceFactor)
        
        
        // delete hash factor key
        let hashFactorPub = try curveSecp256k1.SecretKey(hex: hashFactorKey).toPublic().serialize(compressed: true)
        try await self.deleteFactor(deleteFactorPub: hashFactorPub, deleteFactorKey: hashFactorKey)
        
        if recoveryFactor {
            let recovery = try await self.createFactor(tssShareIndex: .RECOVERY, factorKey: enableMFA.factorKey, factorDescription: enableMFA.factorTypeDescription, additionalMetadata: enableMFA.additionalMetadata)
            return recovery
        }
        return nil
    }
    
//    public async enableMFA(enableMFAParams: EnableMFAParams, recoveryFactor = true): Promise<string> {
//      this.checkReady();
//
//      const hashedFactorKey = getHashedPrivateKey(this.state.oAuthKey, this.options.hashedFactorNonce);
//      if (!(await this.checkIfFactorKeyValid(hashedFactorKey))) {
//        if (this.tKey._localMetadataTransitions[0].length) throw new Error("CommitChanges are required before enabling MFA");
//        throw new Error("MFA already enabled");
//      }
//
//      try {
//        let browserData;
//
//        if (this.isNodejsOrRN(this.options.uxMode)) {
//          browserData = {
//            browserName: "Node Env",
//            browserVersion: "",
//            deviceName: "nodejs",
//          };
//        } else {
//          // try {
//          const browserInfo = bowser.parse(navigator.userAgent);
//          const browserName = `${browserInfo.browser.name}`;
//          browserData = {
//            browserName,
//            browserVersion: browserInfo.browser.version,
//            deviceName: browserInfo.os.name,
//          };
//        }
//        const deviceFactorKey = new BN(await this.createFactor({ shareType: TssShareType.DEVICE, additionalMetadata: browserData }), "hex");
//        if (this.currentStorage instanceof AsyncStorage) {
//          asyncStoreFactor(deviceFactorKey, this, this.options.asyncStorageKey);
//        } else {
//          storeWebBrowserFactor(deviceFactorKey, this, this.options.storageKey);
//        }
//        await this.inputFactorKey(new BN(deviceFactorKey, "hex"));
//
//        const hashedFactorPub = getPubKeyPoint(hashedFactorKey);
//        await this.deleteFactor(hashedFactorPub, hashedFactorKey);
//        await this.deleteMetadataShareBackup(hashedFactorKey);
//
//        // only recovery factor = true
//        if (recoveryFactor) {
//          const backupFactorKey = await this.createFactor({ shareType: TssShareType.RECOVERY, ...enableMFAParams });
//          return backupFactorKey;
//        }
//        // update to undefined for next major release
//        return "";
//      } catch (err: unknown) {
//        log.error("error enabling MFA", err);
//        throw new Error((err as Error).message);
//      }
//    }
    
    private func bootstrapTssClient (selected_tag: String ) async throws -> (TSSClient, [String: String]) {
        
        guard let tkey = self.tkey else {
            throw TSSClientError("invalid tkey")
        }
        
        guard let verifier = self.verifier, let verifierId = self.verifierId , let tssEndpoints = self.tssEndpoints, let factorKey = self.factorKey, let nodeIndexes = self.nodeIndexes else {
            throw TSSClientError("Invalid parameter for tss client")
        }
        
        let tssNonce = try TssModule.get_tss_nonce(threshold_key: tkey, tss_tag: selected_tag)
        
        let compressed = try await TssModule.get_tss_pub_key(threshold_key: tkey, tss_tag: selected_tag)
        
        let publicKey = try curveSecp256k1.PublicKey(hex: compressed).serialize(compressed: false)
        
        let (tssIndex, tssShare) = try await TssModule.get_tss_share(threshold_key: tkey, tss_tag: selected_tag, factorKey: factorKey)
        
        if ( publicKey.count < 128 || publicKey.count > 130 ) {
            throw TSSClientError("Public Key should be in uncompressed format")
        }
        
        // generate a random nonce for sessionID
        let randomKey = try BigUInt(  Data(hexString:  curveSecp256k1.SecretKey().serialize() )! )
        let random = BigInt(sign: .plus, magnitude: randomKey) + BigInt(Date().timeIntervalSince1970)
        let sessionNonce = TSSHelpers.base64ToBase64url( base64: TSSHelpers.hashMessage(message: random.serialize().toHexString()))
        
        // create the full session string
        let session = TSSHelpers.assembleFullSession(verifier: verifier, verifierId: verifierId, tssTag: selected_tag, tssNonce: String(tssNonce), sessionNonce: sessionNonce)

        let userTssIndex = BigInt(tssIndex, radix: 16)!
        // total parties, including the client
        let parties = nodeIndexes.count > 0 ? nodeIndexes.count + 1 : 4

        // index of the client, last index of partiesIndexes
        let clientIndex = Int32(parties - 1)

        let (urls, socketUrls, partyIndexes, nodeInd) = try TSSHelpers.generateEndpoints(parties: parties, clientIndex: Int(clientIndex), nodeIndexes: nodeIndexes, urls: tssEndpoints)

        let coeffs = try TSSHelpers.getServerCoefficients(participatingServerDKGIndexes: nodeInd.map({ BigInt($0) }), userTssIndex: userTssIndex)

        let shareUnsigned = BigUInt(tssShare, radix: 16)!
        let share = BigInt(sign: .plus, magnitude: shareUnsigned)

        let client = try TSSClient(session: session, index: Int32(clientIndex), parties: partyIndexes.map({Int32($0)}), endpoints: urls.map({ URL(string: $0 ?? "") }), tssSocketEndpoints: socketUrls.map({ URL(string: $0 ?? "") }), share: TSSHelpers.base64Share(share: share), pubKey: try TSSHelpers.base64PublicKey(pubKey: Data(hex: publicKey)))

        return (client, coeffs)
     }
}
