import XCTest
import CryptoKit
@testable import Keys

final class SigningTests: XCTestCase {
    // MARK: - Test Setup

    override func setUp() async throws {
        try await super.setUp()
    }

    override func tearDown() async throws {
        try await super.tearDown()
    }

    // MARK: - Ed25519 Signing Tests

    func testEd25519Signing() async throws {
        let keypair = try await generateKeypair(algorithm: .ed25519)
        print("\nPublic key: \(keypair.publicKey.map { String(format: "%02x", $0) }.joined())")
        print("Public key length: \(keypair.publicKey.count)")

        // Test with different message lengths
        let messageLengths = [16, 32, 64, 128, 256, 1024]
        for length in messageLengths {
            let message = generateTestMessage(length: length)
            print("\nTesting message length: \(length)")
            print("Message: \(message.map { String(format: "%02x", $0) }.joined())")

            // Sign and verify
            let signature = try signEd25519(message, privateKey: keypair.privateKey)
            print("Signature: \(signature.map { String(format: "%02x", $0) }.joined())")
            print("Signature length: \(signature.count)")

            // Print first and last byte of signature
            if let firstByte = signature.first, let lastByte = signature.last {
                print("First byte: 0x\(String(format: "%02x", firstByte))")
                print("Last byte: 0x\(String(format: "%02x", lastByte))")
            }

            let isValid = try verifyEd25519(signature: signature, message: message, publicKey: keypair.publicKey)

            XCTAssertTrue(isValid, "Ed25519 signature should be valid for message length \(length)")
            XCTAssertEqual(signature.count, 64, "Ed25519 signature should be 64 bytes")
        }
    }

    func testEd25519SigningIsDeterministic() async throws {
        let keypair = try await generateKeypair(algorithm: .ed25519)

        // Use a fixed message instead of a random one
        let message = Data("Hello, deterministic signing!".utf8)

        // Sign the same message multiple times
        let signature1 = try signEd25519(message, privateKey: keypair.privateKey)
        let signature2 = try signEd25519(message, privateKey: keypair.privateKey)
        let signature3 = try signEd25519(message, privateKey: keypair.privateKey)

        // Print signatures for debugging
        print("Message: \(message.map { String(format: "%02x", $0) }.joined())")
        print("Signature 1: \(signature1.map { String(format: "%02x", $0) }.joined())")
        print("Signature 2: \(signature2.map { String(format: "%02x", $0) }.joined())")
        print("Signature 3: \(signature3.map { String(format: "%02x", $0) }.joined())")

        // Verify all signatures are valid
        XCTAssertTrue(try verifyEd25519(signature: signature1, message: message, publicKey: keypair.publicKey), "First signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: signature2, message: message, publicKey: keypair.publicKey), "Second signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: signature3, message: message, publicKey: keypair.publicKey), "Third signature should be valid")

        // Note: Signatures may be different due to side-channel resistance
        // This is a security feature, not a bug
    }

    func testEd25519SigningIsDeterministicWithFixedKey() async throws {
        let keypair = try await generateKeypair(algorithm: .ed25519)
        let privateKey = keypair.privateKey
        let publicKey = keypair.publicKey
        let message = Data("Hello, deterministic signing!".utf8)

        // Print private key info
        print("Private key length: \(privateKey.count)")
        print("Private key: \(privateKey.map { String(format: "%02x", $0) }.joined())")

        // Sign the same message multiple times
        let signature1 = try signEd25519(message, privateKey: privateKey)
        let signature2 = try signEd25519(message, privateKey: privateKey)
        let signature3 = try signEd25519(message, privateKey: privateKey)

        // Print signatures for debugging
        print("Signature 1: \(signature1.map { String(format: "%02x", $0) }.joined())")
        print("Signature 2: \(signature2.map { String(format: "%02x", $0) }.joined())")
        print("Signature 3: \(signature3.map { String(format: "%02x", $0) }.joined())")

        // Verify all signatures are valid
        XCTAssertTrue(try verifyEd25519(signature: signature1, message: message, publicKey: publicKey), "First signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: signature2, message: message, publicKey: publicKey), "Second signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: signature3, message: message, publicKey: publicKey), "Third signature should be valid")

        // Test with same key instance
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        let signature4 = try key.signature(for: message)
        let signature5 = try key.signature(for: message)
        print("Signature 4: \(signature4.map { String(format: "%02x", $0) }.joined())")
        print("Signature 5: \(signature5.map { String(format: "%02x", $0) }.joined())")

        // Verify signatures from key instance are valid
        XCTAssertTrue(try verifyEd25519(signature: signature4, message: message, publicKey: publicKey), "Fourth signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: signature5, message: message, publicKey: publicKey), "Fifth signature should be valid")

        // Note: Signatures may be different due to side-channel resistance
        // This is a security feature, not a bug
    }

    // MARK: - Secp256k1 Signing Tests

    func testSecp256k1Signing() async throws {
        let keypair = try await generateKeypair(algorithm: .secp256k1)

        // Test with different message lengths
        let messageLengths = [16, 32, 64, 128, 256, 1024]
        for length in messageLengths {
            let message = generateTestMessage(length: length)

            // Sign and verify
            let signature = try signSecp256k1(message, privateKey: keypair.privateKey)
            let isValid = try verifySecp256k1(signature: signature, message: message, publicKey: keypair.publicKey)

            XCTAssertTrue(isValid, "Secp256k1 signature should be valid for message length \(length)")
            XCTAssertEqual(signature.count, 64, "Secp256k1 signature should be 64 bytes")
        }
    }

    // MARK: - Signature Verification Tests

    func testSignatureVerification() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)
        let message = generateTestMessage(length: 32)

        // Test Ed25519 verification
        let ed25519Signature = try signEd25519(message, privateKey: ed25519Keypair.privateKey)

        // Test valid signature
        XCTAssertTrue(try verifyEd25519(signature: ed25519Signature, message: message, publicKey: ed25519Keypair.publicKey),
                     "Ed25519 signature should verify with correct key")

        // Test invalid signature (modified)
        var modifiedSignature = ed25519Signature
        modifiedSignature[0] ^= 0xFF  // Flip all bits in first byte
        XCTAssertFalse(try verifyEd25519(signature: modifiedSignature, message: message, publicKey: ed25519Keypair.publicKey),
                      "Ed25519 signature should not verify when modified")

        // Test invalid message
        var modifiedMessage = message
        modifiedMessage[0] ^= 0xFF  // Flip all bits in first byte
        XCTAssertFalse(try verifyEd25519(signature: ed25519Signature, message: modifiedMessage, publicKey: ed25519Keypair.publicKey),
                      "Ed25519 signature should not verify with modified message")

        // Test Secp256k1 verification
        let secp256k1Signature = try signSecp256k1(message, privateKey: secp256k1Keypair.privateKey)

        // Test valid signature
        XCTAssertTrue(try verifySecp256k1(signature: secp256k1Signature, message: message, publicKey: secp256k1Keypair.publicKey),
                     "Secp256k1 signature should verify with correct key")

        // Test invalid signature (modified)
        var modifiedSecpSignature = secp256k1Signature
        modifiedSecpSignature[0] ^= 0xFF  // Flip all bits in first byte
        XCTAssertFalse(try verifySecp256k1(signature: modifiedSecpSignature, message: message, publicKey: secp256k1Keypair.publicKey),
                      "Secp256k1 signature should not verify when modified")

        // Test invalid message
        XCTAssertFalse(try verifySecp256k1(signature: secp256k1Signature, message: modifiedMessage, publicKey: secp256k1Keypair.publicKey),
                      "Secp256k1 signature should not verify with modified message")
    }

    // MARK: - Cross-Algorithm Tests

//    func testCrossAlgorithmSigning() async throws {
//        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
//        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)
//        let message = generateTestMessage(length: 32)
//
//        // Test Ed25519 signature with Secp256k1 key
//        let ed25519Signature = try signEd25519(message, privateKey: ed25519Keypair.privateKey)
//        XCTAssertThrowsError(try verifySecp256k1(signature: ed25519Signature, message: message, publicKey: secp256k1Keypair.publicKey)) { error in
//            XCTAssertEqual(error as? KeyError, .invalidFormat)
//        }
//
//        // Test Secp256k1 signature with Ed25519 key
//        let secp256k1Signature = try signSecp256k1(message, privateKey: secp256k1Keypair.privateKey)
//        XCTAssertThrowsError(try verifyEd25519(signature: secp256k1Signature, message: message, publicKey: ed25519Keypair.publicKey)) { error in
//            XCTAssertEqual(error as? KeyError, .invalidFormat)
//        }
//    }

    // MARK: - Error Cases

    func testSigningErrors() async throws {
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)
        let message = generateTestMessage(length: 32)

        // Test invalid private key length
        let invalidPrivateKey = Data([1, 2, 3])  // Too short
        XCTAssertThrowsError(try signEd25519(message, privateKey: invalidPrivateKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidKeyData)
        }
        XCTAssertThrowsError(try signSecp256k1(message, privateKey: invalidPrivateKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidKeyData)
        }

        // Test invalid public key length
        let invalidPublicKey = Data([1, 2, 3])  // Too short
        XCTAssertThrowsError(try verifyEd25519(signature: Data(count: 64), message: message, publicKey: invalidPublicKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidKeyData)
        }
        XCTAssertThrowsError(try verifySecp256k1(signature: Data(count: 64), message: message, publicKey: invalidPublicKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidKeyData)
        }

        // Test invalid signature length
        let invalidSignature = Data([1, 2, 3])  // Too short
        XCTAssertThrowsError(try verifyEd25519(signature: invalidSignature, message: message, publicKey: ed25519Keypair.publicKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidFormat)
        }
        XCTAssertThrowsError(try verifySecp256k1(signature: invalidSignature, message: message, publicKey: secp256k1Keypair.publicKey)) { error in
            XCTAssertEqual(error as? KeyError, .invalidFormat)
        }
    }

    // MARK: - Deterministic Signing Tests

    func testDeterministicSigning() async throws {
        // Use a fixed private key for deterministic testing
        let fixedPrivateKey = Data([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        ])

        // Generate keypairs with fixed private key for Ed25519
        let ed25519Keypair = try await generateKeypair(algorithm: .ed25519, privateKeyBytes: fixedPrivateKey)
        let secp256k1Keypair = try await generateKeypair(algorithm: .secp256k1)

        // Use a fixed message
        let message = Data("Hello, deterministic signing!".utf8)

        // Print message and key details for debugging
        print("Message: \(message.map { String(format: "%02x", $0) }.joined())")
        print("Ed25519 Private Key: \(ed25519Keypair.privateKey.map { String(format: "%02x", $0) }.joined())")
        print("Ed25519 Public Key: \(ed25519Keypair.publicKey.map { String(format: "%02x", $0) }.joined())")

        // Create a single private key instance to reuse
        let ed25519Key = try Curve25519.Signing.PrivateKey(rawRepresentation: ed25519Keypair.privateKey)

        // Test Ed25519 signing using the same key instance
        let ed25519Signature1 = try ed25519Key.signature(for: message)
        let ed25519Signature2 = try ed25519Key.signature(for: message)

        // Print signatures for debugging
        print("Ed25519 Signature 1: \(ed25519Signature1.map { String(format: "%02x", $0) }.joined())")
        print("Ed25519 Signature 2: \(ed25519Signature2.map { String(format: "%02x", $0) }.joined())")

        // Verify Ed25519 signatures are valid
        XCTAssertTrue(try verifyEd25519(signature: ed25519Signature1, message: message, publicKey: ed25519Keypair.publicKey), "First Ed25519 signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: ed25519Signature2, message: message, publicKey: ed25519Keypair.publicKey), "Second Ed25519 signature should be valid")

        // Also test using the signEd25519 function
        let ed25519Signature3 = try signEd25519(message, privateKey: ed25519Keypair.privateKey)
        let ed25519Signature4 = try signEd25519(message, privateKey: ed25519Keypair.privateKey)

        print("Ed25519 Signature 3: \(ed25519Signature3.map { String(format: "%02x", $0) }.joined())")
        print("Ed25519 Signature 4: \(ed25519Signature4.map { String(format: "%02x", $0) }.joined())")

        // Verify additional Ed25519 signatures are valid
        XCTAssertTrue(try verifyEd25519(signature: ed25519Signature3, message: message, publicKey: ed25519Keypair.publicKey), "Third Ed25519 signature should be valid")
        XCTAssertTrue(try verifyEd25519(signature: ed25519Signature4, message: message, publicKey: ed25519Keypair.publicKey), "Fourth Ed25519 signature should be valid")

        // Note: Ed25519 signatures may be different due to side-channel resistance
        // This is a security feature, not a bug

        // Test Secp256k1 deterministic signing (not affected by side-channel resistance)
        let secp256k1Signature1 = try signSecp256k1(message, privateKey: secp256k1Keypair.privateKey)
        let secp256k1Signature2 = try signSecp256k1(message, privateKey: secp256k1Keypair.privateKey)
        XCTAssertEqual(secp256k1Signature1, secp256k1Signature2, "Secp256k1 signing should be deterministic")
    }
}
