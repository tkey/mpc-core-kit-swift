import XCTest
@testable import mpc_core_kit_swift
import JWTKit
import curveSecp256k1
import SingleFactorAuth

// JWT payload structure.
struct TestPayload: JWTPayload, Equatable {
    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case expiration = "exp"
        case isAdmin = "admin"
        case emailVerified = "email_verified"
        case issuer = "iss"
        case iat
        case email
        case audience = "aud"
    }

    var subject: SubjectClaim
    var expiration: ExpirationClaim
    var audience: AudienceClaim
    var isAdmin: Bool
    let emailVerified: Bool
    var issuer: IssuerClaim
    var iat: IssuedAtClaim
    var email: String

    // call its verify method.
    func verify(using signer: JWTSigner) throws {
        try expiration.verifyNotExpired()
    }
}

func mockLogin( email: String) async throws -> Data {
    // Create URL
    let url = URL(string: "https://li6lnimoyrwgn2iuqtgdwlrwvq0upwtr.lambda-url.eu-west-1.on.aws/")!

    // Create URLRequest
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    // Create JSON data to send in the request body
//verifier: "torus-key-test", scope: "email", extraPayload: { email }, alg: "ES256"
    let jsonObject: [String: Any] = [
        "verifier": "torus-test-health",
        "scope": email,
        "extraPayload" : [
            "email" : email
        ],
        "alg" : "ES256"
    ]
    let jsonData = try JSONSerialization.data(withJSONObject: jsonObject)
    request.httpBody = jsonData
    
    // Perform the request asynchronously
    let (data, _) = try await URLSession.shared.data(for: request)

    return data
}

func mockLogin2 (email:String) throws -> String {
    
        let verifierPrivateKeyForSigning =
            """
            -----BEGIN PRIVATE KEY-----
            MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==
            -----END PRIVATE KEY-----
            """

        do {
            let signers = JWTSigners()
            let keys = try ECDSAKey.private(pem: verifierPrivateKeyForSigning)
            signers.use(.es256(key: keys))

            // Parses the JWT and verifies its signature.
            let today = Date()
            let modifiedDate = Calendar.current.date(byAdding: .hour, value: 1, to: today)!

            let emailComponent = email.components(separatedBy: "@")[0]
            let subject = "email|" + emailComponent

            let payload = TestPayload(subject: SubjectClaim(stringLiteral: subject), expiration: ExpirationClaim(value: modifiedDate), audience: "torus-key-test", isAdmin: false, emailVerified: true, issuer: "torus-key-test", iat: IssuedAtClaim(value: Date()), email: email)
            let jwt = try signers.sign(payload)
            return jwt
        } catch {
            throw error
        }
    
}


final class mpc_kit_swiftTests: XCTestCase {
    
    func resetMPC(email: String, verifier: String, clientId: String) async throws {
        var coreKitInstance = MpcCoreKit( web3AuthClientId: clientId, web3AuthNetwork: Web3AuthNetwork.SAPPHIRE_DEVNET, disableHashFactor: false, localStorage: MemoryStorage() )
        let data = try  mockLogin2(email: email)
        let token = data
        
        
        let keyDetails = try await coreKitInstance.loginWithJwt(verifier: verifier, verifierId: email, idToken: token)
        try await coreKitInstance.resetAccount()
    }
    
    func testExample() async throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        
        let email = "testiosEmail004"
        let verifier = "torus-test-health"
        let clientId = "torus-test-health"
        try await resetMPC(email: email, verifier: verifier, clientId: clientId)
        
        let memoryStorage = MemoryStorage()
        var coreKitInstance = MpcCoreKit( web3AuthClientId: clientId, web3AuthNetwork: Web3AuthNetwork.SAPPHIRE_DEVNET, disableHashFactor: false, localStorage: memoryStorage)
        
        let data = try  mockLogin2(email: email)
        let token = data
//        let dataObj = try JSONSerialization.jsonObject(with: data) as! [String: String]
        
//        let token = dataObj["token"]!
        
//        if let jsonString = String(data: data, encoding: .utf8) {
//                  print("Response: \(jsonString)")
//                  // Parse JSON response data here using JSONDecoder or other methods
//              }
//        let jwtParams : IdTokenLoginParams = .init(verifier: verifier, verifierId: email, idToken: token, domain: "com.ios.mpc" )
//        let keyDetails = try await coreKitInstance.login(loginProvider: .jwt, verifier: "test", jwtParams: jwtParams.toDictionary())
        

        let keyDetails = try await coreKitInstance.loginWithJwt(verifier: verifier, verifierId: email, idToken: token)
        
        let hash = try keccak256(data: Data(hex: "010203040506"))
        let signatures = try await coreKitInstance.tssSign(message: hash)
        print(signatures)
        //
        let newFactor = try await coreKitInstance.createFactor(tssShareIndex: .DEVICE, factorKey: nil, factorDescription: .DeviceShare , additionalMetadata: ["my":"mymy"])
        
        let deleteFactorPub = try curveSecp256k1.SecretKey(hex: newFactor).toPublic().serialize(compressed: true)
        try await coreKitInstance.deleteFactor(deleteFactorPub: deleteFactorPub, deleteFactorKey: newFactor)
        print (keyDetails)
        
    }
    
    func testRecoveryFactor() async throws  {
        
        let email = "testiosEmail11mfa"
        let verifier = "torus-test-health"
        let clientId = "torus-test-health"
        try await resetMPC(email: email, verifier: verifier, clientId: clientId)
        let memoryStorage = MemoryStorage()
        var coreKitInstance = MpcCoreKit( web3AuthClientId: clientId, web3AuthNetwork: Web3AuthNetwork.SAPPHIRE_DEVNET, disableHashFactor: false, localStorage: memoryStorage)
        let data = try  mockLogin2(email: email)
        let token = data
        
        
        let keyDetails = try await coreKitInstance.loginWithJwt(verifier: verifier, verifierId: email, idToken: token)

        let hash = try Data(hex: "010203040506").sha3(varient:Variants.KECCAK256)
        guard let recoveryFactor = try await coreKitInstance.enableMFA() else { throw "empty factor" };

        let memoryStorage2 = MemoryStorage()
        var coreKitInstance2 = MpcCoreKit( web3AuthClientId: "torus-test-health", web3AuthNetwork: Web3AuthNetwork.SAPPHIRE_DEVNET, disableHashFactor: false, localStorage: memoryStorage2);
        let data2 = try  mockLogin2(email: email)
        let token2 = data2
        
        
        let keyDetails2 = try await coreKitInstance2.loginWithJwt(verifier: verifier, verifierId: email, idToken: token2)
        
        try await coreKitInstance2.inputFactor(factorKey: recoveryFactor)
        let result = try await coreKitInstance.createFactor(tssShareIndex: .DEVICE, factorKey: nil, factorDescription: .DeviceShare)
        
        let getKeyDetails = try await coreKitInstance2.getKeyDetails()
        XCTAssertEqual(getKeyDetails.requiredFactors, 0);

        let userInfo = try coreKitInstance2.getUserInfo();
        if let verifierId = userInfo["verifierId"] as? String {
            XCTAssertEqual(verifierId, email);
        } else {
            XCTFail("Verifier ID not matching.")
        }
        
        let hash2 =  try Data(hex: "010203040506").sha3(varient: Variants.KECCAK256)
        let signatures2 = try await coreKitInstance2.tssSign(message: hash2)
    }
}
