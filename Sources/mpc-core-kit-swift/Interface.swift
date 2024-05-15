//
//  File.swift
//  
//
//  Created by CW Lee on 23/01/2024.
//

import Foundation
import tkey
import SingleFactorAuth

public protocol ILocalStorage {
    func set(key:String, payload: Data ) async throws -> Void
    func get(key:String) async throws -> Data
}


public protocol IFactorStorage {
    func setFactor(metadataPubKey:String, factorKey: String ) async throws -> Void
    func getFactor(metadataPubKey:String) async throws -> String
}

public struct CoreKitOptions {
    public var disableHashFactor : Bool
    public var Web3AuthClientId : String
    public var network : Web3AuthNetwork
}

public struct CoreKitAppState :Codable, Equatable {
    public var factorKey: String? = nil
    public var metadataPubKey: String? = nil
    
    // share index used for backup share recovery
    public var deviceMetadataShareIndex: String? = nil
    
    public var loginTime : Date? = nil
    
    init(factorKey: String? = nil, metadataPubKey: String? = nil, deviceMetadataShareIndex: String? = nil, loginTime: Date? = nil) {
        self.factorKey = factorKey
        self.metadataPubKey = metadataPubKey
        self.deviceMetadataShareIndex = deviceMetadataShareIndex
        self.loginTime = loginTime
    }
    
    // Method to merge data from another instance of MyStruct
    mutating func merge(with other: CoreKitAppState) {
        // Update properties based on merging logic
        if (other.factorKey != nil) {
            self.factorKey = other.factorKey
        }
        if (other.metadataPubKey != nil) {
            self.metadataPubKey = other.metadataPubKey
        }
        if (other.deviceMetadataShareIndex != nil) {
            self.deviceMetadataShareIndex = other.deviceMetadataShareIndex
        }
        if (other.loginTime != nil) {
            self.loginTime = other.loginTime
        }
    }
}

public struct MpcKeyDetails : Codable {
    public let tssPubKey : String
    public let metadataPubKey: String
    public let requiredFactors: Int32
    public let threshold: UInt32
    public let shareDescriptions : String
    public let total_shares: UInt32
    public let totalFactors: UInt32?
//    public let requiredFactors: String
}

public struct IdTokenLoginParams {
  /**
   * Name of the verifier created on Web3Auth Dashboard. In case of Aggregate Verifier, the name of the top level aggregate verifier.
   */
  public var verifier: String

  /**
   * Unique Identifier for the User. The verifier identifier field set for the verifier/ sub verifier. E.g. "sub" field in your on jwt id token.
   */
  public var verifierId: String

  /**
   * The idToken received from the Auth Provider.
   */
  public var idToken: String

  /**
   * Name of the sub verifier in case of aggregate verifier setup. This field should only be provided in case of an aggregate verifier.
   */
  public var subVerifier: String?

  /**
   * Extra verifier params in case of a WebAuthn verifier type.
   */
//  public var extraVerifierParams?: WebAuthnExtraParams;

//  /**
//   * Any additional parameter (key value pair) you'd like to pass to the login function.
//   */
//  public var additionalParams: [String: Any]?

  /**
   * Key to import key into Tss during first time login.
   */
//  public var importTssKey?: String
    
    public var domain: String?
    
    public func toDictionary () throws -> [String:String]{
        var dict : [String: String] = [:]
        // Using Mirror to loop through struct members
        let mirror = Mirror(reflecting: self)
        for case let (label?, value) in mirror.children {
            if let value = value as? String {
                dict[label] = value
            }
        }
        return dict
    }
}

public enum FactorDescriptionTypeModule {
    case HashedShare
    case SecurityQuestions
    case DeviceShare
    case SeedPhrase
    case PasswordShare
    case SocialShare
    case Other 
  
    public func toString () -> String {
        switch self {
            
        case .HashedShare: return "hashedShare"
        case .SecurityQuestions: return "tssSecurityQuestions"
        case .DeviceShare: return "deviceShare"
        case .SeedPhrase: return "seedPhrase"
        case .PasswordShare: return "passwordShare"
        case .SocialShare: return "socialShare"
        case .Other: return "Other"
        }
    }
}

public enum TssShareType {
    case DEVICE
    case RECOVERY
    
    public func toInt32 () -> Int32 {
        switch self {
            
        case .DEVICE: return 2
        case .RECOVERY: return 3
        }
    }
    public func toString () -> String {
        switch self {
            
        case .DEVICE: return "2"
        case .RECOVERY: return "3"
        }
    }
}

public struct enableMFARecoveryFactor {
    public var factorKey: String?
    public var factorTypeDescription: FactorDescriptionTypeModule
    public var additionalMetadata: [String:Any]
    
    public init(factorKey: String? = nil, factorTypeDescription: FactorDescriptionTypeModule = .Other, additionalMetadata: [String : Any] = [:]) {
        self.factorKey = factorKey
        self.factorTypeDescription = factorTypeDescription
        self.additionalMetadata = additionalMetadata
    }
}

public enum LoginType: String, Codable {
    case google = "google"
    case facebook = "facebook"
    case reddit = "reddit"
    case discord = "discord"
    case twitch = "twitch"
    case apple = "apple"
    case line = "line"
    case github = "github"
    case kakao = "kakao"
    case linkedin = "linkedin"
    case twitter = "twitter"
    case weibo = "weibo"
    case wechat = "wechat"
    case farcaster = "farcaster"
    case emailPasswordless = "email_passwordless"
    case smsPasswordless = "sms_passwordless"
    case webauthn = "webauthn"
    case jwt = "jwt"
}

public struct WebAuthnExtraParams: Codable {
    public let authenticatorAttachment: String?
    public let attestation: String?
    public let userVerification: String?
}

public struct TorusGenericObject: Codable {
    public let type: String?
    public let verifier: String?
    public let verifierIdField: String?
}

public struct TorusVerifierResponse: Codable {
    public let email: String
    public let name: String
    public let profileImage: String
    public let aggregateVerifier: String?
    public let verifier: String
    public let verifierId: String
    public let typeOfLogin: LoginType
    public let ref: String?
    public let registerOnly: Bool?
    public let extraVerifierParams: WebAuthnExtraParams?
}

public struct LoginWindowResponse: Codable {
    public let accessToken: String
    public let idToken: String?
    public let ref: String?
    public let extraParams: String?
    public let extraParamsPassed: String?
    public let state: TorusGenericObject
}

public struct UserInfo: Codable {
    public let email: String?
    public let name: String?
    public let profileImage: String?
    public let aggregateVerifier: String?
    public let verifier: String
    public let verifierId: String
    public let typeOfLogin: LoginType?
    public let ref: String?
    public let registerOnly: Bool?
    public let extraVerifierParams: WebAuthnExtraParams?
    public let accessToken: String?
    public let idToken: String?
    public let extraParams: String?
    public let extraParamsPassed: String?
    public let state: TorusGenericObject?
}

enum UserInfoConversionError: Error, LocalizedError {
    case missingData
    case invalidData
    case decodingError(Error)
    
    var errorDescription: String? {
        switch self {
        case .missingData:
            return "UserInfo dictionary is missing."
        case .invalidData:
            return "UserInfo dictionary is invalid."
        case .decodingError(let error):
            return "Error decoding UserInfo: \(error.localizedDescription)"
        }
    }
}

