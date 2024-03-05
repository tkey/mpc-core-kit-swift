//
//  File.swift
//  
//
//  Created by CW Lee on 07/02/2024.
//

import Foundation

public class CoreKitStorage {
    internal static var instance : CoreKitStorage? ;
    
    public var storage : ILocalStorage
    private var storeKey : String
    
    public init(storeKey : String, storage: ILocalStorage) {
        self.storage = storage
        self.storeKey = storeKey
    }
    
//    static func getInstance( storeKey: String , storage: ILocalStorage? = nil) throws -> CoreKitStorage {
//        guard let localInstance = self.instance else {
//            guard let lStorage = storage else {
//                throw "no storage provided or found"
//            }
//            let local = CoreKitStorage.init(storeKey: storeKey, storage: lStorage)
//            CoreKitStorage.instance = local
//            return local
//        }
//        return localInstance
//    }
    
    public func resetStore() async throws -> Data {
        let result = try await self.storage.get(key: self.storeKey)
        let payload = try JSONSerialization.data(withJSONObject: [:])
        
        try await self.storage.set(key: self.storeKey, payload: payload)
        
        return result
    }
    
    public func toJsonStr() async throws -> String {
        let result = try await self.storage.get(key: self.storeKey)
        guard let resultStr = String(data: result, encoding: .utf8) else {
            throw "invalid store"
        }
        return resultStr
    }
    
    public func getStore() async throws -> [String: Codable] {
        let result = try await self.storage.get(key: self.storeKey)
        if result.isEmpty { return [:] }
        let store = try JSONSerialization.jsonObject(with: result) as? [String: Codable]
        guard let storeUnwrapped = store else {
            return [:]
        }
        return storeUnwrapped
    }
    
    public func get<T>(key:String) async throws -> T {
        let store = try await self.getStore()
        
        guard let item = store[key] as? T else {
            throw "key \(key) value  not found"
        }
        return item
    }
    
    public func set<T>(key:String, payload: T) async throws {
        var store : [String:Any] = try await self.getStore()
        store.updateValue( payload, forKey: key)
        
        let jsonData = try JSONSerialization.data(withJSONObject: store)
        try await self.storage.set(key: self.storeKey, payload: jsonData)
    }
    
    public func remove(key:String) async throws {
        var store = try await self.getStore()
        store[key] = nil
        let jsonData = try JSONSerialization.data(withJSONObject: store)
        try await self.storage.set(key: self.storeKey, payload: jsonData)
    }
    
}

// Example implementation of Factor Storage Protocol (Interface)
class DeviceFactorStorage : IFactorStorage {
    let storage: CoreKitStorage
    
    public init(storage: CoreKitStorage) {
        self.storage = storage
    }
    
    public func setFactor(metadataPubKey: String, factorKey: String) async throws {
        var localMetadata : [String: Codable] = [:]
        let result : [String: Codable]?  = try? await self.storage.get(key: metadataPubKey)
        if let result = result {
            localMetadata = result
        }
        localMetadata["factorKey"] = factorKey
        try await self.storage.set(key: metadataPubKey, payload: localMetadata)
    }
    
    public func getFactor(metadataPubKey: String) async throws -> String {
        let localMetadata : [String: Codable]?  = try? await self.storage.get(key: metadataPubKey)
        guard let localMetadata = localMetadata, let deviceFactor = localMetadata["factorKey"] as? String else {
            throw "device factor not found"
        }
        return deviceFactor
    }
}


extension MpcCoreKit {
    public func getDeviceFactor () async throws -> String {
        // getMetadataPublicKey compressed
        guard let metadataPubKey = self.appState.metadataPubKey else {
            throw "metadataPubKey is not available"
        }
        
        let deviceFactorStorage = DeviceFactorStorage(storage: self.coreKitStorage)
        return try await deviceFactorStorage.getFactor(metadataPubKey: metadataPubKey)
    }
    
    public func setDeviceFactor ( factorKey: String ) async throws {
        guard let metadataPubKey = self.appState.metadataPubKey else {
            throw "metadataPubKey is not available"
        }
        let deviceFactorStorage = DeviceFactorStorage(storage: self.coreKitStorage)
        try await deviceFactorStorage.setFactor(metadataPubKey: metadataPubKey, factorKey: factorKey)
    }
    
    internal func resetDeviceFactorStore () async throws {
        guard let metadataPubKey = self.appState.metadataPubKey else {
            throw "metadataPubKey is not available"
        }
        try await self.coreKitStorage.set(key: metadataPubKey, payload: [:])
    }
}
