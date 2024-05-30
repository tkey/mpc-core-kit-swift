//
//  File.swift
//  
//
//  Created by CW Lee on 16/01/2024.
//

import Foundation
import tssClientSwift
import tkey
import BigInt
import curveSecp256k1
import FetchNodeDetails
import SingleFactorAuth


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


public func hashMessage(message: String) throws -> String {
    return try TSSHelpers.hashMessage(message: message)
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

public func parseToken(jwtToken jwt: String) -> [String: Any] {
  let segments = jwt.components(separatedBy: ".")
  return decodeJWTPart(segments[1]) ?? [:]
}

func base64UrlDecode(_ value: String) -> Data? {
  var base64 = value
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")

  let length = Double(base64.lengthOfBytes(using: String.Encoding.utf8))
  let requiredLength = 4 * ceil(length / 4.0)
  let paddingLength = requiredLength - length
  if paddingLength > 0 {
    let padding = "".padding(toLength: Int(paddingLength), withPad: "=", startingAt: 0)
    base64 = base64 + padding
  }
  return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
}

func decodeJWTPart(_ value: String) -> [String: Any]? {
  guard let bodyData = base64UrlDecode(value),
    let json = try? JSONSerialization.jsonObject(with: bodyData, options: []), let payload = json as? [String: Any] else {
      return nil
  }

  return payload
}
