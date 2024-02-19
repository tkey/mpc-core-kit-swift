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
import curveSecp256k1

func convertPublicKeyFormat ( publicKey: String, outFormat: PublicKeyEncoding ) throws -> String {
    let point = try KeyPoint(address: publicKey)
    let result = try point.getPublicKey(format: outFormat)
    return result
}


public func createCoreKitFactorDescription ( module: FactorDescriptionTypeModule, tssIndex: TssShareType, additional : [String:Codable] = [:] ) -> [String: Codable] {
    var description = additional
    
    description["module"] = module.toString()
    description["tssShareIndex"] = tssIndex.toString()
    description["dateAdded"] = Date().timeIntervalSince1970
    
    return description
}

func factorDescriptionToJsonStr ( dataObj: [String: Codable]  ) throws -> String {
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

public class MemoryStorage : ILocalStorage {
    var memory : [String:Data] = [:]
    
    public func get(key: String) async throws -> Data {
        guard let result = memory[key] else {
            return Data()
        }
        return result
    }
    
    public func set(key: String, payload: Data) async throws {
        memory.updateValue(payload, forKey: key)
    }
}
