//
//  File.swift
//  
//
//  Created by CW Lee on 16/01/2024.
//

import Foundation
import tss_client_swift
import BigInt
import curvelib

public func bootstrapTssClient (selected_tag: String, tssNonce: Int32, publicKey: String, tssShare: String, tssIndex: String, nodeIndexes: [Int], factorKey: String, verifier: String, verifierId: String, tssEndpoints: [String] ) throws -> (TSSClient, [String: String]) {
    if ( publicKey.count < 128 || publicKey.count > 130 ) {
        throw RuntimeError("Public Key should be in uncompressed format")
    }
    
    // generate a random nonce for sessionID
    let randomKey = try BigUInt(curvelib.Secp256k1.PrivateKey().rawData)
    let random = BigInt(sign: .plus, magnitude: randomKey) + BigInt(Date().timeIntervalSince1970)
    let sessionNonce = TSSHelpers.hashMessage(message: String(random))
    // create the full session string
    let session = TSSHelpers.assembleFullSession(verifier: verifier, verifierId: verifierId, tssTag: selected_tag, tssNonce: String(tssNonce), sessionNonce: sessionNonce.base64EncodedString())

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



public func hashMessage(message: Data) -> String {
    let hash = message.sha3(.keccak256)
    return hash.base64EncodedString()
}

public func hashMessage(message: String) -> String {
    return hashMessage(message: Data(message.utf8))
}

