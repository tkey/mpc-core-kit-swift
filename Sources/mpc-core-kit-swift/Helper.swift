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

import SingleFactorAuth

import CommonSources

func convertPublicKeyFormat ( publicKey: String, outFormat: PublicKeyEncoding ) throws -> String {
    let point = try KeyPoint(address: publicKey)
    let result = try point.getPublicKey(format: outFormat)
    return result
}


public func createCoreKitFactorDescription ( module: FactorDescriptionTypeModule, tssIndex: TssShareType, additional : [String:Any] = [:] ) -> [String: Any] {
    var description = additional
    
    description["module"] = module.toString()
    description["tssShareIndex"] = tssIndex.toString()
    description["dateAdded"] = Date().timeIntervalSince1970
    
    return description
}

func factorDescriptionToJsonStr ( dataObj: [String: Any]  ) throws -> String {
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


func convertWeb3AuthNetworkToTorusNetWork ( network: Web3AuthNetwork ) -> TorusNetwork {
    switch network {
    case Web3AuthNetwork.SAPPHIRE_DEVNET : return .sapphire(.SAPPHIRE_DEVNET);
    case Web3AuthNetwork.SAPPHIRE_MAINNET : return .sapphire(.SAPPHIRE_MAINNET);
    case Web3AuthNetwork.MAINNET : return .legacy(.MAINNET);
    case Web3AuthNetwork.TESTNET: return .legacy(.TESTNET);
    case Web3AuthNetwork.CYAN: return .legacy(.CYAN);
    case Web3AuthNetwork.AQUA: return .legacy(.AQUA);
    case Web3AuthNetwork.CELESTE: return .legacy(.CELESTE);
    case Web3AuthNetwork.CUSTOM(_): return .sapphire(.SAPPHIRE_MAINNET);
    }
}

public extension Web3AuthNetwork {
    func toTorusNetwork () -> TorusNetwork{
        return convertWeb3AuthNetworkToTorusNetWork(network: self)
    }
}
