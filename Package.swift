// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AgentCommerceKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "AgentCommerceKit", targets: ["AgentCommerceKit"]),
        .library(name: "Identity", targets: ["Identity"]),
        .library(name: "Payment", targets: ["Payment"]),
        .library(name: "DID", targets: ["DID"]),
        .library(name: "JWT", targets: ["JWT"]),
        .library(name: "Keys", targets: ["Keys"]),
        .library(name: "VC", targets: ["VC"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.21.1"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(
            name: "AgentCommerceKit",
            dependencies: [
                "Identity",
                "Payment",
                "DID",
                "JWT",
                "Keys",
                "VC"
            ]
        ),
        .target(
            name: "Identity",
            dependencies: ["DID", "VC"]
        ),
        .target(
            name: "Payment",
            dependencies: ["DID", "JWT", "VC"]
        ),
        .target(
            name: "DID",
            dependencies: ["Keys"]
        ),
        .target(
            name: "JWT",
            dependencies: ["Keys"]
        ),
        .target(
            name: "Keys",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "P256K", package: "swift-secp256k1"),
                .product(name: "BigInt", package: "BigInt")
            ]
        ),
        .target(
            name: "VC",
            dependencies: ["DID", "JWT"]
        ),

        // Test targets for each module
        .testTarget(
            name: "AgentCommerceKitTests",
            dependencies: ["AgentCommerceKit"]
        ),
        .testTarget(
            name: "IdentityTests",
            dependencies: ["Identity"]
        ),
        .testTarget(
            name: "PaymentTests",
            dependencies: ["Payment"]
        ),
        .testTarget(
            name: "DIDTests",
            dependencies: ["DID"]
        ),
        .testTarget(
            name: "JWTTests",
            dependencies: ["JWT"]
        ),
        .testTarget(
            name: "KeysTests",
            dependencies: ["Keys"]
        ),
        .testTarget(
            name: "VCTests",
            dependencies: ["VC"]
        )
    ]
)
