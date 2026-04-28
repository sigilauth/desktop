// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SigilAuth",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SigilAuth",
            targets: ["SigilAuth"]
        ),
        .executable(
            name: "SigilAuthApp",
            targets: ["SigilAuthApp"]
        ),
        .executable(
            name: "crypto-sign",
            targets: ["SigilCryptoSign"]
        )
    ],
    dependencies: [
    ],
    targets: [
        // C Argon2 reference implementation
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            sources: ["src/argon2.c", "src/core.c", "src/ref.c", "src/encoding.c", "src/thread.c", "src/blake2/blake2b.c"],
            publicHeadersPath: "include",
            cSettings: [
                .define("ARGON2_NO_THREADS")
            ]
        ),

        // Core library
        .target(
            name: "SigilAuth",
            dependencies: ["CArgon2"],
            path: "Sources/SigilAuth",
            resources: [
                .copy("../../Resources/Localization"),
                .copy("../../Resources/pictogram-pool-v1.json")
            ]
        ),

        // macOS app executable
        .executableTarget(
            name: "SigilAuthApp",
            dependencies: ["SigilAuth"],
            path: "Sources/SigilAuthApp",
            resources: [
                .process("Resources")
            ]
        ),

        // CryptoSign CLI tool
        .executableTarget(
            name: "SigilCryptoSign",
            dependencies: ["SigilAuth"],
            path: "Sources/SigilCryptoSign"
        ),

        // Unit tests
        .testTarget(
            name: "SigilAuthTests",
            dependencies: ["SigilAuth"],
            path: "Tests/SigilAuthTests",
            resources: [
                .copy("TestVectors")
            ]
        )
    ]
)
