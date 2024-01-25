//
//  File.swift
//  
//
//  Created by CW Lee on 16/01/2024.
//

import Foundation
import tss_client_swift
import tkey_mpc_swift
import BigInt
import curvelib_swift

func convertPublicKeyFormat ( publicKey: String, outFormat: PublicKeyEncoding ) throws -> String {
    let point = try KeyPoint(address: publicKey)
    let result = try point.getPublicKey(format: outFormat)
    return result
}

func factorDescription ( dataObj: [String: Codable]  ) throws -> String {
    let json = try JSONSerialization.data(withJSONObject: dataObj)
    guard let jsonStr = String(data: json, encoding: .utf8) else {
        throw "Invalid data structure"
    }
    return jsonStr
}


public func hashMessage(message: Data) -> String {
    let hash = message.sha3(.keccak256)
    return hash.base64EncodedString()
}

public func hashMessage(message: String) -> String {
    return hashMessage(message: Data(message.utf8))
}

