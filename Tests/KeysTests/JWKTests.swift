import XCTest
@testable import Keys

final class JWKTests: XCTestCase {
    // MARK: - Test Setup

    override func setUp() async throws {
        try await super.setUp()
    }

    override func tearDown() async throws {
        try await super.tearDown()
    }

    // MARK: - JWK Format Tests

    func testJWKFormat() async throws {
        // Test JWK format for both key types
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 JWK format
        let ed25519Jwk = try JWK.encodePublicKey(ed25519Keypair.publicKey, algorithm: .ed25519)
        if case .ed25519(let key) = ed25519Jwk {
            XCTAssertEqual(key.kty, "OKP", "Ed25519 JWK should have kty=OKP")
            XCTAssertEqual(key.crv, "Ed25519", "Ed25519 JWK should have crv=Ed25519")
            XCTAssertFalse(key.x.isEmpty, "Ed25519 JWK should have non-empty x coordinate")
        } else {
            XCTFail("Ed25519 JWK should be Ed25519PublicKey type")
        }

        // Test Secp256k1 JWK format
        let secp256k1Jwk = try JWK.encodePublicKey(secp256k1Keypair.publicKey, algorithm: .secp256k1)
        if case .secp256k1(let key) = secp256k1Jwk {
            XCTAssertEqual(key.kty, "EC", "Secp256k1 JWK should have kty=EC")
            XCTAssertEqual(key.crv, "secp256k1", "Secp256k1 JWK should have crv=secp256k1")
            XCTAssertFalse(key.x.isEmpty, "Secp256k1 JWK should have non-empty x coordinate")
            XCTAssertFalse(key.y.isEmpty, "Secp256k1 JWK should have non-empty y coordinate")
        } else {
            XCTFail("Secp256k1 JWK should be Secp256k1PublicKey type")
        }
    }

    // MARK: - JWK Compression Tests

    func testSecp256k1Compression() async throws {
        // Test that JWK always uses uncompressed format for Secp256k1
        let keypair = try await generateKeypair(algorithm: .secp256k1)

        // Verify input is compressed (33 bytes)
        XCTAssertEqual(keypair.publicKey.count, 33, "Input Secp256k1 key should be compressed")
        XCTAssertTrue(keypair.publicKey[0] == 0x02 || keypair.publicKey[0] == 0x03,
                     "Input Secp256k1 key should start with 0x02 or 0x03")

        // Convert to JWK and back
        let jwk = try JWK.encodePublicKey(keypair.publicKey, algorithm: .secp256k1)
        let jwkString = try JSONEncoder().encode(jwk)
        let decodedKey = try JWK.decodePublicKey(String(data: jwkString, encoding: .utf8)!, algorithm: .secp256k1)

        // Verify output is uncompressed (65 bytes)
        XCTAssertEqual(decodedKey.count, 65, "JWK decoded Secp256k1 key should be uncompressed")
        XCTAssertEqual(decodedKey[0], 0x04, "JWK decoded Secp256k1 key should start with 0x04")

        // Verify x-coordinate matches
        XCTAssertEqual(decodedKey[1..<33], keypair.publicKey[1..<33],
                      "JWK decoded Secp256k1 key x-coordinate should match")
    }

    // MARK: - JWK Private Key Tests

    func testJWKPrivateKey() async throws {
        // Test JWK private key format
        let keypair = try await generateKeypair(algorithm: .secp256k1)
        let jwk = try JWK.keypairToJwk(keypair)

        // Verify private key format
        XCTAssertFalse(jwk.d.isEmpty, "JWK private key should have non-empty d value")

        // Convert back to keypair
        let recoveredKeypair = try JWK.jwkToKeypair(jwk)

        // Verify keypair recovery
        switch keypair.algorithm {
        case .secp256k1:
            // For Secp256k1, JWK always returns uncompressed format (65 bytes)
            XCTAssertEqual(recoveredKeypair.publicKey.count, 65, "JWK decoded Secp256k1 key should be uncompressed (65 bytes)")
            XCTAssertEqual(recoveredKeypair.publicKey[0], 0x04, "JWK decoded Secp256k1 key should start with 0x04")
            // Verify the x-coordinate matches (bytes 1-32)
            XCTAssertEqual(
                recoveredKeypair.publicKey[1..<33],
                keypair.publicKey[1..<33],
                "JWK decoded Secp256k1 key x-coordinate should match"
            )
        default:
            // For other algorithms, the key should match exactly
            XCTAssertEqual(recoveredKeypair.publicKey, keypair.publicKey,
                          "Recovered public key should match original")
        }

        // Private key and algorithm should always match
        XCTAssertEqual(recoveredKeypair.privateKey, keypair.privateKey,
                      "Recovered private key should match original")
        XCTAssertEqual(recoveredKeypair.algorithm, keypair.algorithm,
                      "Recovered algorithm should match original")
    }

    // MARK: - JWK Validation Tests

    func testJWKValidation() async throws {
        // Test JWK validation
        let keypair = try await generateKeypair(algorithm: .secp256k1)
        let jwk = try JWK.keypairToJwk(keypair)
        let jwkString = try JSONEncoder().encode(jwk)

        // Test valid JWK
        XCTAssertTrue(JWK.isValidPublicKey(String(data: jwkString, encoding: .utf8)!, algorithm: .secp256k1),
                     "Valid JWK should pass validation")

        // Test invalid JWK (wrong algorithm)
        XCTAssertFalse(JWK.isValidPublicKey(String(data: jwkString, encoding: .utf8)!, algorithm: .ed25519),
                      "JWK with wrong algorithm should fail validation")

        // Test invalid JWK (malformed JSON)
        XCTAssertFalse(JWK.isValidPublicKey("invalid json", algorithm: .secp256k1),
                      "Invalid JSON should fail validation")
    }

    // MARK: - JWK Roundtrip Tests

    func testJWKRoundtrip() async throws {
        // Test JWK roundtrip for both key types
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test Ed25519 roundtrip
        let ed25519Jwk = try JWK.keypairToJwk(ed25519Keypair)
        let ed25519JwkString = try JSONEncoder().encode(ed25519Jwk)
        let recoveredEd25519Keypair = try JWK.jwkToKeypair(ed25519Jwk)
        XCTAssertEqual(recoveredEd25519Keypair.publicKey, ed25519Keypair.publicKey,
                      "Ed25519 public key should survive JWK roundtrip")
        XCTAssertEqual(recoveredEd25519Keypair.privateKey, ed25519Keypair.privateKey,
                      "Ed25519 private key should survive JWK roundtrip")

        // Test Secp256k1 roundtrip
        let secp256k1Jwk = try JWK.keypairToJwk(secp256k1Keypair)
        let secp256k1JwkString = try JSONEncoder().encode(secp256k1Jwk)
        let recoveredSecp256k1Keypair = try JWK.jwkToKeypair(secp256k1Jwk)

        // For Secp256k1, JWK always returns uncompressed format (65 bytes)
        XCTAssertEqual(recoveredSecp256k1Keypair.publicKey.count, 65,
                      "JWK decoded Secp256k1 key should be uncompressed (65 bytes)")
        XCTAssertEqual(recoveredSecp256k1Keypair.publicKey[0], 0x04,
                      "JWK decoded Secp256k1 key should start with 0x04")
        // Verify the x-coordinate matches (bytes 1-32)
        XCTAssertEqual(
            recoveredSecp256k1Keypair.publicKey[1..<33],
            secp256k1Keypair.publicKey[1..<33],
            "JWK decoded Secp256k1 key x-coordinate should match"
        )
        XCTAssertEqual(recoveredSecp256k1Keypair.privateKey, secp256k1Keypair.privateKey,
                      "Secp256k1 private key should survive JWK roundtrip")
    }
}
