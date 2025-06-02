import XCTest
@testable import Keys

// MARK: - Keypair Assertions

extension XCTestCase {
    /// Assert that a keypair has valid properties for its algorithm
    func assertValidKeypair(_ keypair: Keypair, algorithm: KeypairAlgorithm, file: StaticString = #file, line: UInt = #line) {
        XCTAssertEqual(keypair.algorithm, algorithm, "Keypair algorithm should match expected algorithm", file: file, line: line)

        switch algorithm {
        case .ed25519:
            XCTAssertEqual(keypair.publicKey.count, 32, "Ed25519 public key should be 32 bytes", file: file, line: line)
            XCTAssertEqual(keypair.privateKey.count, 32, "Ed25519 private key should be 32 bytes", file: file, line: line)

        case .secp256k1:
            XCTAssertEqual(keypair.publicKey.count, 33, "Secp256k1 public key should be 33 bytes (compressed)", file: file, line: line)
            XCTAssertEqual(keypair.privateKey.count, 32, "Secp256k1 private key should be 32 bytes", file: file, line: line)

            // Verify Secp256k1 public key format
            let firstByte = keypair.publicKey[0]
            XCTAssertTrue(
                firstByte == 0x02 || firstByte == 0x03,
                "Secp256k1 public key should start with 0x02 or 0x03",
                file: file,
                line: line
            )
        }
    }

    /// Assert that two keypairs are different
    func assertKeypairsAreDifferent(_ keypair1: Keypair, _ keypair2: Keypair, file: StaticString = #file, line: UInt = #line) {
        XCTAssertNotEqual(
            keypair1.publicKey,
            keypair2.publicKey,
            "Generated public keys should be unique",
            file: file,
            line: line
        )
        XCTAssertNotEqual(
            keypair1.privateKey,
            keypair2.privateKey,
            "Generated private keys should be unique",
            file: file,
            line: line
        )
    }
}

// MARK: - Test Data Generation

extension XCTestCase {
    /// Generate a test message of specified length
    func generateTestMessage(length: Int = 32) -> Data {
        var message = Data(count: length)
        message.withUnsafeMutableBytes { buffer in
            _ = SecRandomCopyBytes(kSecRandomDefault, length, buffer.baseAddress!)
        }
        return message
    }

    /// Generate multiple test keypairs
    func generateTestKeypairs(count: Int, algorithm: KeypairAlgorithm) async throws -> [Keypair] {
        var keypairs: [Keypair] = []
        for _ in 0..<count {
            let keypair = try await generateKeypair(algorithm: algorithm)
            keypairs.append(keypair)
        }
        return keypairs
    }
}

// MARK: - Encoding Test Helpers

extension XCTestCase {
    /// Assert that a key can be encoded and decoded in all supported formats
    func assertKeyEncodingRoundtrip(_ keypair: Keypair, file: StaticString = #file, line: UInt = #line) throws {
        // Test all supported encodings
        let encodings: [PublicKeyEncoding] = [.hex, .base58, .multibase, .jwk]

        for encoding in encodings {
            // Encode public key
            let encoded: Any
            switch encoding {
            case .hex, .base58, .multibase:
                encoded = try encodePublicKey(keypair.publicKey, algorithm: keypair.algorithm, encoding: encoding) as String
            case .jwk:
                encoded = try encodePublicKey(keypair.publicKey, algorithm: keypair.algorithm, encoding: encoding) as JWK.PublicKey
            }

            // Decode public key based on encoding type
            let decoded: Data
            switch encoding {
            case .hex, .base58, .multibase:
                guard let encodedString = encoded as? String else {
                    XCTFail("Encoded key should be a String for \(encoding) encoding", file: file, line: line)
                    return
                }
                decoded = try decodePublicKey(encodedString, algorithm: keypair.algorithm, encoding: encoding)

            case .jwk:
                guard let encodedJWK = encoded as? JWK.PublicKey else {
                    XCTFail("Encoded key should be a JWK.PublicKey for JWK encoding", file: file, line: line)
                    return
                }
                let jwkString = try JSONEncoder().encode(encodedJWK)
                decoded = try decodePublicKey(String(data: jwkString, encoding: .utf8)!, algorithm: keypair.algorithm, encoding: encoding)
            }

            // Verify roundtrip
            switch (keypair.algorithm, encoding) {
            case (.secp256k1, .jwk):
                // For Secp256k1 JWK, we need to handle the format difference
                // JWK always returns uncompressed (65 bytes) while input might be compressed (33 bytes)
                XCTAssertEqual(decoded.count, 65, "JWK decoded Secp256k1 key should be uncompressed (65 bytes)", file: file, line: line)
                XCTAssertEqual(decoded[0], 0x04, "JWK decoded Secp256k1 key should start with 0x04", file: file, line: line)
                // Verify the x-coordinate matches (bytes 1-32)
                XCTAssertEqual(
                    decoded[1..<33],
                    keypair.publicKey[1..<33],
                    "JWK decoded Secp256k1 key x-coordinate should match",
                    file: file,
                    line: line
                )

            default:
                // For all other cases, the decoded key should exactly match the original
                XCTAssertEqual(
                    decoded,
                    keypair.publicKey,
                    "Public key should survive \(encoding) encoding/decoding roundtrip",
                    file: file,
                    line: line
                )
            }
        }
    }
}

// MARK: - Signing Test Helpers

extension XCTestCase {
    /// Assert that a keypair can sign and verify a message
    func assertSignAndVerify(_ keypair: Keypair, message: Data, file: StaticString = #file, line: UInt = #line) throws {
        let signature: Data
        let isValid: Bool

        switch keypair.algorithm {
        case .ed25519:
            signature = try signEd25519(message, privateKey: keypair.privateKey)
            isValid = try verifyEd25519(signature: signature, message: message, publicKey: keypair.publicKey)

            // Test with modified message for Ed25519
            var modifiedMessage = message
            modifiedMessage[0] ^= 0xFF // Flip all bits in first byte
            let isValidModified = try verifyEd25519(
                signature: signature,
                message: modifiedMessage,
                publicKey: keypair.publicKey
            )
            XCTAssertFalse(isValidModified, "Ed25519 signature should be invalid for modified message", file: file, line: line)

        case .secp256k1:
            signature = try signSecp256k1(message, privateKey: keypair.privateKey)
            isValid = try verifySecp256k1(signature: signature, message: message, publicKey: keypair.publicKey)

            // Test with modified message for Secp256k1
            var modifiedMessage = message
            modifiedMessage[0] ^= 0xFF // Flip all bits in first byte
            let isValidModified = try verifySecp256k1(
                signature: signature,
                message: modifiedMessage,
                publicKey: keypair.publicKey
            )
            XCTAssertFalse(isValidModified, "Secp256k1 signature should be invalid for modified message", file: file, line: line)
        }

        XCTAssertTrue(isValid, "Signature should be valid", file: file, line: line)
    }
}
