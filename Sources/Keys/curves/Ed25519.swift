import Foundation
import Crypto
import P256K
import BigInt

/// Generate a new Ed25519 key pair
public func generateEd25519Keypair(privateKeyBytes: Data? = nil) async throws -> Keypair {
    let privateKey: Data
    if let providedKey = privateKeyBytes {
        privateKey = providedKey
    } else {
        privateKey = generatePrivateKeyBytes()
    }

    let publicKey = try getPublicKey(from: privateKey)
    return Keypair(
        publicKey: publicKey,
        privateKey: privateKey,
        algorithm: .ed25519
    )
}

/// Convert an Ed25519 key pair to JWK format
///
/// - Parameter keypair: The Ed25519 key pair to convert
/// - Returns: A JWK private key object
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the key pair is not Ed25519
///
/// # Example
/// ```swift
/// let keypair = try await generateEd25519Keypair()
/// let jwk = try ed25519KeypairToJwk(keypair)
/// // jwk is a JWK.PrivateKey object
/// ```
public func ed25519KeypairToJwk(_ keypair: Keypair) throws -> JWK.PrivateKey {
    guard keypair.algorithm == .ed25519 else {
        throw KeyError.unsupportedAlgorithm
    }
    return try JWK.keypairToJwk(keypair)
}

/// Convert a JWK to an Ed25519 key pair
///
/// - Parameter jwk: The JWK private key to convert
/// - Returns: An Ed25519 key pair
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the JWK is not for Ed25519
///
/// # Example
/// ```swift
/// let jwk: JWK.PrivateKey = // ... get JWK from somewhere
/// let keypair = try jwkToEd25519Keypair(jwk)
/// // keypair is a Keypair with algorithm .ed25519
/// ```
public func jwkToEd25519Keypair(_ jwk: JWK.PrivateKey) throws -> Keypair {
    let keypair = try JWK.jwkToKeypair(jwk)
    guard keypair.algorithm == .ed25519 else {
        throw KeyError.unsupportedAlgorithm
    }
    return keypair
}

// MARK: - Private Helpers

private func generatePrivateKeyBytes() -> Data {
    let key = Curve25519.Signing.PrivateKey()
    return key.rawRepresentation
}

private func getPublicKey(from privateKey: Data) throws -> Data {
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
    return key.publicKey.rawRepresentation
}

/// Sign a message using an Ed25519 private key
public func signEd25519(_ message: Data, privateKey: Data) throws -> Data {
    // Create a private key from the raw bytes
    do {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)

        // Sign the message using CryptoKit's Ed25519 implementation
        // This should be deterministic as per the Ed25519 specification
        // Note: Apple's CryptoKit implementation adds side-channel resistance by making the signatures non-deterministic
        return try key.signature(for: message)
    } catch {
        // Convert CryptoKit errors to KeyError.invalidKeyData
        throw KeyError.invalidKeyData
    }
}

/// Check if a signature is in secp256k1 format
/// secp256k1 signatures are 64 bytes long and consist of two 32-byte components (R and S)
/// - Parameter signature: The signature to check
/// - Returns: True if the signature appears to be in secp256k1 format
///
/// Note: This function is currently disabled but kept for future cross-algorithm validation
public func isSecp256k1Signature(_ signature: Data) -> Bool {
    return false
}

/// Verify a signature using an Ed25519 public key
public func verifyEd25519(signature: Data, message: Data, publicKey: Data) throws -> Bool {
    // Validate signature format - Ed25519 signatures are 64 bytes
    guard signature.count == 64 else {
        throw KeyError.invalidFormat
    }

    // Validate public key format - Ed25519 public keys are 32 bytes
    guard publicKey.count == 32 else {
        throw KeyError.invalidKeyData
    }

    // Check if this is a secp256k1 signature
    // if isSecp256k1Signature(signature) {
    //     throw KeyError.invalidFormat
    // }

    // Debug: Print public key bytes
    print("\nVerifying with public key: \(publicKey.map { String(format: "%02x", $0) }.joined())")
    print("Public key length: \(publicKey.count)")

    // Try to parse the public key and verify the signature using CryptoKit
    do {
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: message)
    } catch {
        print("Error parsing public key: \(error)")
        throw KeyError.invalidKeyData
    }
}
