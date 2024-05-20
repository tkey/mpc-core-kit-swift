//
//  File.swift
//  
//
//  Created by CW Lee on 20/05/2024.
//

import Foundation
import mpc_core_kit_swift

public protocol ISigner {
    func sign( message: Data ) -> Data
    var publicKey : Data { get }
}


extension MpcCoreKit : ISigner {
    public func sign(message: Data) -> Data {
        let data =  try? self.tssSign(message: message)
        return data ?? Data([])
    }

    
    public var publicKey: Data {
        return self.getTssPubKey().suffix(64)
    }
    
}
