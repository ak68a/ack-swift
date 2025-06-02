import XCTest
@testable import Keys

final class KeyGenerationTests: XCTestCase {
    // MARK: - Test Setup

    override func setUp() async throws {
        try await super.setUp()
        // Any setup code that needs to run before each test
    }

    override func tearDown() async throws {
        // Any cleanup code that needs to run after each test
        try await super.tearDown()
    }

    // MARK: - Ed25519 Key Generation Tests

    func testGenerateEd25519Keypair() async throws {
        // Test basic Ed25519 keypair generation
        let keypair = try await generateKeypair(algorithm: .ed25519)
        assertValidKeypair(keypair, algorithm: .ed25519)
    }

    func testEd25519KeypairUniqueness() async throws {
        // Test that generated Ed25519 keypairs are unique
        let keypair1 = try await generateKeypair(algorithm: .ed25519)
        let keypair2 = try await generateKeypair(algorithm: .ed25519)
        assertKeypairsAreDifferent(keypair1, keypair2)
    }

    // MARK: - Secp256k1 Key Generation Tests

    func testGenerateSecp256k1Keypair() async throws {
        // Test basic Secp256k1 keypair generation
        let keypair = try await generateKeypair(algorithm: .secp256k1)
        assertValidKeypair(keypair, algorithm: .secp256k1)
    }

    func testSecp256k1KeypairUniqueness() async throws {
        // Test that generated Secp256k1 keypairs are unique
        let keypair1 = try await generateKeypair(algorithm: .secp256k1)
        let keypair2 = try await generateKeypair(algorithm: .secp256k1)
        assertKeypairsAreDifferent(keypair1, keypair2)
    }

    // MARK: - Bulk Generation Tests

    func testGenerateMultipleKeypairs() async throws {
        // Test generating multiple keypairs of each type
        let ed25519Keypairs = try await generateTestKeypairs(count: 10, algorithm: .ed25519)
        let secp256k1Keypairs = try await generateTestKeypairs(count: 10, algorithm: .secp256k1)

        // Verify all keypairs are valid
        for keypair in ed25519Keypairs {
            assertValidKeypair(keypair, algorithm: .ed25519)
        }
        for keypair in secp256k1Keypairs {
            assertValidKeypair(keypair, algorithm: .secp256k1)
        }

        // Verify all keypairs are unique
        for i in 0..<ed25519Keypairs.count {
            for j in (i+1)..<ed25519Keypairs.count {
                assertKeypairsAreDifferent(ed25519Keypairs[i], ed25519Keypairs[j])
            }
        }
        for i in 0..<secp256k1Keypairs.count {
            for j in (i+1)..<secp256k1Keypairs.count {
                assertKeypairsAreDifferent(secp256k1Keypairs[i], secp256k1Keypairs[j])
            }
        }
    }

    // MARK: - Integration Tests

    func testKeypairSigningAndVerification() async throws {
        // Test that generated keypairs can sign and verify messages
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test with different message lengths
        let messageLengths = [16, 32, 64, 128, 256]
        for length in messageLengths {
            let message = generateTestMessage(length: length)

            // Test Ed25519
            try assertSignAndVerify(ed25519Keypair, message: message)

            // Test Secp256k1
            try assertSignAndVerify(secp256k1Keypair, message: message)
        }
    }

    func testKeypairEncodingRoundtrip() async throws {
        // Test that generated keypairs can be encoded and decoded
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test encoding roundtrip for both keypairs
        try assertKeyEncodingRoundtrip(ed25519Keypair)
        try assertKeyEncodingRoundtrip(secp256k1Keypair)
    }
}
