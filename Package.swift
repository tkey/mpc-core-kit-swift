// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "mpc-core-kit-swift",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "mpc-core-kit-swift",
            targets: ["mpc-core-kit-swift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/torusresearch/tss-client-swift.git", from: "2.0.1"),
        .package(url: "https://github.com/tkey/tkey-mpc-swift", branch: "2.0.1"),
        .package(url: "https://github.com/torusresearch/customauth-swift-sdk", branch: "feat/web3authClientId"),
        .package(url: "https://github.com/Web3Auth/single-factor-auth-swift", branch: "feat/update-torusUtils"),
        
            .package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0")
        
    ],
    
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "mpc-core-kit-swift",
            dependencies: ["tss-client-swift",
                .product(name: "tkey-mpc-swift", package: "tkey-mpc-swift" ),
                .product(name: "CustomAuth", package: "customauth-swift-sdk"),
                .product(name: "SingleFactorAuth", package: "single-factor-auth-swift")
                           
            ]
        ),
        .testTarget(
            name: "mpc-kit-swiftTests",
            dependencies: ["mpc-core-kit-swift", .product(name: "JWTKit", package: "jwt-kit")]),
    ]
)
