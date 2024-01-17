//
//  File.swift
//
//
//  Created by CW Lee on 10/01/2024.
//

import Foundation
import tkey_mpc_swift
import tss_client_swift


public struct MpcSigningKit  {

    public var tkey : ThresholdKey;
    public var selectedTag: String;
    public var tssEndpoints: [String];
    public var authSigs: [String];
    public var verifier: String;
    public var verifierId: String;
    public var factorKey: String;
    public var tssIndex: String;
    public var tssShare: String;
    public var tssNonce: Int32;
    
    public var nodeIndexes: [Int];
    
    public var publicKey: String;
    
    public init(tkey: ThresholdKey, factorKey : String ,
                verifier: String, verifierId: String, tssEndPoints: [String], authSigs: [String], nodeIndexes: [Int] = [], selecteTag: String = "default" ) async throws {
        self.tkey = tkey;
        self.selectedTag = selecteTag

        self.factorKey = factorKey;
        let (tssIndex, tssShare) = try await TssModule.get_tss_share(threshold_key: self.tkey, tss_tag: self.selectedTag, factorKey: self.factorKey)
        let tssNonce = try TssModule.get_tss_nonce(threshold_key: tkey, tss_tag: selecteTag)
        
        self.tssIndex = tssIndex
        self.tssShare = tssShare
        self.tssNonce = tssNonce
        
        self.verifier = verifier;
        self.verifierId = verifierId;
        self.authSigs = authSigs
        self.tssEndpoints = tssEndPoints;
        
        self.nodeIndexes = nodeIndexes
        
        self.publicKey = try await TssModule.get_tss_pub_key(threshold_key: tkey, tss_tag: selecteTag)
        
    }
    
    /// Signing Data without hashing
    public func sign(message: Data) throws -> Data {
        // Create tss Client using helper
        let (client, coeffs) = try bootstrapTssClient(selected_tag: self.selectedTag, tssNonce: self.tssNonce, publicKey: self.publicKey, tssShare: self.tssShare, tssIndex: self.tssIndex, nodeIndexes: self.nodeIndexes, factorKey: self.factorKey, verifier: self.verifier, verifierId: self.verifierId, tssEndpoints: self.tssEndpoints)

        // Wait for sockets to be connected
        let connected = try client.checkConnected()
        if !(connected) {
            throw "Client not connected"
        }

        let precompute = try client.precompute(serverCoeffs: coeffs, signatures: self.authSigs)
        let ready = try client.isReady()
        if !(ready) {
            throw RuntimeError("Error, client not ready")
        }
        
        let signingMessage = message.base64EncodedString()
        let (s, r, v) = try! client.sign(message: signingMessage, hashOnly: true, original_message: "", precompute: precompute, signatures: self.authSigs)

        try! client.cleanup(signatures: self.authSigs)

        return r + s + Data([v])
    }
}


