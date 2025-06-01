import Foundation
import Crypto
import P256K

/// Generate a new secp256k1 key pair
public func generateSecp256k1Keypair(privateKeyBytes: Data? = nil) async throws -> Keypair {
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
        algorithm: .secp256k1
    )
}

/// Convert a secp256k1 key pair to JWK format
///
/// - Parameter keypair: The secp256k1 key pair to convert
/// - Returns: A JWK private key object
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the key pair is not secp256k1
///
/// # Example
/// ```swift
/// let keypair = try await generateSecp256k1Keypair()
/// let jwk = try secp256k1KeypairToJwk(keypair)
/// // jwk is a JWK.PrivateKey object
/// ```
public func secp256k1KeypairToJwk(_ keypair: Keypair) throws -> JWK.PrivateKey {
    guard keypair.algorithm == .secp256k1 else {
        throw KeyError.unsupportedAlgorithm
    }
    return try JWK.keypairToJwk(keypair)
}

/// Convert a JWK to a secp256k1 key pair
///
/// - Parameter jwk: The JWK private key to convert
/// - Returns: A secp256k1 key pair
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the JWK is not for secp256k1
///
/// # Example
/// ```swift
/// let jwk: JWK.PrivateKey = // ... get JWK from somewhere
/// let keypair = try jwkToSecp256k1Keypair(jwk)
/// // keypair is a Keypair with algorithm .secp256k1
/// ```
public func jwkToSecp256k1Keypair(_ jwk: JWK.PrivateKey) throws -> Keypair {
    let keypair = try JWK.jwkToKeypair(jwk)
    guard keypair.algorithm == .secp256k1 else {
        throw KeyError.unsupportedAlgorithm
    }
    return keypair
}

// MARK: - Private Helpers

private func generatePrivateKeyBytes() -> Data {
    // Generate 32 random bytes for private key
    var privateKey = Data(count: 32)
    privateKey.withUnsafeMutableBytes { buffer in
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
    }
    return privateKey
}

private func getPublicKey(from privateKey: Data) throws -> Data {
    let _ = try P256K.Context.create()
    let seckey = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
    let pubkey = seckey.publicKey
    return pubkey.dataRepresentation
}

/// Sign a message using a secp256k1 private key
public func signSecp256k1(_ message: Data, privateKey: Data) throws -> Data {
    let _ = try P256K.Context.create()
    let seckey = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
    let signature = try seckey.signature(for: message)
    return signature.dataRepresentation
}

/// Verify a signature using a secp256k1 public key
public func verifySecp256k1(signature: Data, message: Data, publicKey: Data) throws -> Bool {
    let _ = try P256K.Context.create()
    let pubkey = try P256K.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed)
    let sig = try P256K.Signing.ECDSASignature(dataRepresentation: signature)
    return pubkey.isValidSignature(sig, for: message)
}
