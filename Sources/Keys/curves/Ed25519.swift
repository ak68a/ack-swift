import Foundation
import Crypto

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
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
    return try key.signature(for: message)
}

/// Verify a signature using an Ed25519 public key
public func verifyEd25519(signature: Data, message: Data, publicKey: Data) throws -> Bool {
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
    return key.isValidSignature(signature, for: message)
}
