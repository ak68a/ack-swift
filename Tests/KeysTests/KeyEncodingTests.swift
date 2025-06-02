import XCTest
@testable import Keys

final class KeyEncodingTests: XCTestCase {
    // MARK: - Test Setup

    override func setUp() async throws {
        try await super.setUp()
    }

    override func tearDown() async throws {
        try await super.tearDown()
    }

    // MARK: - Hex Encoding Tests

    func testHexEncoding() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 hex encoding
        let ed25519Hex = try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .hex) as String
        XCTAssertFalse(ed25519Hex.hasPrefix("0x"), "Hex encoding should not include 0x prefix")
        XCTAssertEqual(ed25519Hex.count, 64, "Ed25519 hex encoding should be 64 hex chars")

        // Test Secp256k1 hex encoding
        let secp256k1Hex = try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .hex) as String
        XCTAssertFalse(secp256k1Hex.hasPrefix("0x"), "Hex encoding should not include 0x prefix")
        XCTAssertEqual(secp256k1Hex.count, 66, "Secp256k1 hex encoding should be 66 hex chars")

        // Test roundtrip
        let decodedEd25519 = try decodePublicKey(ed25519Hex, algorithm: .ed25519, encoding: .hex)
        XCTAssertEqual(decodedEd25519, ed25519Keypair.publicKey, "Ed25519 hex roundtrip should preserve key")

        let decodedSecp256k1 = try decodePublicKey(secp256k1Hex, algorithm: .secp256k1, encoding: .hex)
        XCTAssertEqual(decodedSecp256k1, secp256k1Keypair.publicKey, "Secp256k1 hex roundtrip should preserve key")
    }

    // MARK: - Base58 Encoding Tests

    func testBase58Encoding() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 Base58 encoding
        let ed25519Base58 = try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .base58) as String
        XCTAssertFalse(ed25519Base58.isEmpty, "Base58 encoding should not be empty")
        XCTAssertTrue(Base58.isValid(ed25519Base58), "Base58 encoding should only contain valid characters")

        // Test Secp256k1 Base58 encoding
        let secp256k1Base58 = try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .base58) as String
        XCTAssertFalse(secp256k1Base58.isEmpty, "Base58 encoding should not be empty")
        XCTAssertTrue(Base58.isValid(secp256k1Base58), "Base58 encoding should only contain valid characters")

        // Test roundtrip
        let decodedEd25519 = try decodePublicKey(ed25519Base58, algorithm: .ed25519, encoding: .base58)
        XCTAssertEqual(decodedEd25519, ed25519Keypair.publicKey, "Ed25519 Base58 roundtrip should preserve key")

        let decodedSecp256k1 = try decodePublicKey(secp256k1Base58, algorithm: .secp256k1, encoding: .base58)
        XCTAssertEqual(decodedSecp256k1, secp256k1Keypair.publicKey, "Secp256k1 Base58 roundtrip should preserve key")
    }

    // MARK: - Multibase Encoding Tests

    func testMultibaseEncoding() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 Multibase encoding
        let ed25519Multibase = try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .multibase) as String
        XCTAssertTrue(ed25519Multibase.hasPrefix("z"), "Multibase encoding should start with 'z'")
        XCTAssertTrue(Multibase.isValid(ed25519Multibase), "Ed25519 Multibase encoding should be valid")

        // Test Secp256k1 Multibase encoding
        let secp256k1Multibase = try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .multibase) as String
        XCTAssertTrue(secp256k1Multibase.hasPrefix("z"), "Multibase encoding should start with 'z'")
        XCTAssertTrue(Multibase.isValid(secp256k1Multibase), "Secp256k1 Multibase encoding should be valid")

        // Test roundtrip
        let decodedEd25519 = try decodePublicKey(ed25519Multibase, algorithm: .ed25519, encoding: .multibase)
        XCTAssertEqual(decodedEd25519, ed25519Keypair.publicKey, "Ed25519 Multibase roundtrip should preserve key")

        let decodedSecp256k1 = try decodePublicKey(secp256k1Multibase, algorithm: .secp256k1, encoding: .multibase)
        XCTAssertEqual(decodedSecp256k1, secp256k1Keypair.publicKey, "Secp256k1 Multibase roundtrip should preserve key")
    }

    // MARK: - Error Cases

    func testEncodingErrors() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test invalid key lengths
        let invalidKey = Data([1, 2, 3])  // Too short
        XCTAssertThrowsError(try encodePublicKey(invalidKey, algorithm: .ed25519, encoding: .hex) as String) { error in
            XCTAssertEqual(error as? EncodingError, .unsupportedAlgorithm)
        }

        // Test invalid encoding format - try to encode with an unsupported format
        // Note: This test is commented out since all encoding formats in PublicKeyEncoding are supported
        // If we add a new unsupported format in the future, we can uncomment this test
        // XCTAssertThrowsError(try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .unsupported) as String) { error in
        //     XCTAssertEqual(error as? EncodingError, .unsupportedAlgorithm)
        // }

        // Test invalid multibase string
        XCTAssertThrowsError(try decodePublicKey("invalid", algorithm: .ed25519, encoding: .multibase)) { error in
            XCTAssertEqual(error as? EncodingError, .invalidFormat)
        }

        // Test wrong algorithm for encoding
        XCTAssertThrowsError(try encodePublicKey(ed25519Keypair.publicKey, algorithm: .secp256k1, encoding: .hex) as String) { error in
            XCTAssertEqual(error as? EncodingError, .unsupportedAlgorithm)
        }
    }

    // MARK: - Format Validation

    func testFormatValidation() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 format validation
        XCTAssertTrue(Hex.isValidPublicKey(try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .hex) as String, algorithm: .ed25519))
        XCTAssertTrue(Base58.isValidPublicKey(try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .base58) as String, algorithm: .ed25519))
        XCTAssertTrue(Multibase.isValid(try encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519, encoding: .multibase) as String))

        // Test Secp256k1 format validation
        XCTAssertTrue(Hex.isValidPublicKey(try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .hex) as String, algorithm: .secp256k1))
        XCTAssertTrue(Base58.isValidPublicKey(try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .base58) as String, algorithm: .secp256k1))
        XCTAssertTrue(Multibase.isValid(try encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1, encoding: .multibase) as String))

        // Test invalid formats
        XCTAssertFalse(Hex.isValidPublicKey("0xinvalid", algorithm: .ed25519))
        XCTAssertFalse(Base58.isValidPublicKey("invalid", algorithm: .ed25519))
        XCTAssertFalse(Multibase.isValid("invalid"))
    }
}
