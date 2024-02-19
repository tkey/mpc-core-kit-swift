import XCTest
@testable import mpc_core_kit_swift

final class mpc_kit_swiftTests: XCTestCase {
    func testExample() async throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        
        let memoryStorage = MemoryStorage()
        var coreKitInstance = MpcCoreKit(web3AuthClientId: "", web3AuthNetwork: .sapphire(.SAPPHIRE_DEVNET), localStorage: memoryStorage)
        
        let jwtParams: [String: String] = [ : ]
        let keyDetails = try await coreKitInstance.login(loginProvider: .jwt, verifier: "test", jwtParams: jwtParams)
        
        print (keyDetails)
        
    }
}
