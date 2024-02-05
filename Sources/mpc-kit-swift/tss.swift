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

let semaphoreTimeout = 100_000_000_000

extension MpcSigningKit {
    
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
        //gepoubkey
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
    
    public func createFactor() {
        // check for index is same as factor key
        // create new factor if different index
        // copy if same index
    }
    
    public func deleteFactor ( deleteFactorPub: String, deleteFactorKey: String? = nil) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey, let sigs = self.authSigs else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        
        // delete backup metadata share with factorkey
        if let deleteFactorKey = deleteFactorKey {
            // set metadata to Not Found
        }
        
        try await TssModule.delete_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, delete_factor_pub: deleteFactorPub, nodeDetails: nodeDetails!, torusUtils: torusUtils)
    }
    
    private func copyFactor ( newFactorKey: String, tssShareIndex: Int32 ) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)
        
        // backup metadata share with factorkey
        let shareIndex = try self.getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)
        
        try await TssModule.copy_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factorKey: factorKey, newFactorPub: newFactorPub, tss_index: tssShareIndex)
    }
    
    private func addNewFactor ( newFactorKey: String, tssShareIndex: Int32 ) async throws {
        guard let threshold_key = self.tkey, let factorKey = self.factorKey, let sigs = self.authSigs else {
            throw "Invalid tkey"
        }
        let selectedTag = try TssModule.get_tss_tag(threshold_key: threshold_key)
        
        let newkey = try curveSecp256k1.SecretKey(hex: newFactorKey)
        let newFactorPub = try newkey.toPublic().serialize(compressed: true)
        
        // backup metadata share with factorkey
        let shareIndex = try self.getDeviceMetadataShareIndex()
        try TssModule.backup_share_with_factor_key(threshold_key: threshold_key, shareIndex: shareIndex, factorKey: newFactorKey)
        
        try await TssModule.add_factor_pub(threshold_key: threshold_key, tss_tag: selectedTag, factor_key: factorKey, auth_signatures: sigs, new_factor_pub: newFactorPub, new_tss_index: tssShareIndex, nodeDetails: nodeDetails!, torusUtils: torusUtils)
    }
    
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
