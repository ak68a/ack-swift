/// # AgentCommerceKit Swift SDK - Client SDK Boundaries
///
/// The Swift SDK is designed as a client-side implementation for iOS/macOS applications.
/// It serves as a bridge between your iOS app and our backend services, with clear
/// responsibilities and boundaries.
///
/// ## Important Note:
/// This SDK does NOT handle sensitive operations directly. All sensitive operations
/// (payment processing, KYC verification, etc.) are delegated to backend services.
/// The SDK's role is to provide a secure and efficient way to interact with these services
/// from iOS applications.
///
/// - Author: AgentCommerceKit Team
/// - Version: 1.0.0
/// - Copyright: © 2025 AgentCommerceKit. All rights reserved.

import Foundation
import Crypto

/// Generate a new key pair for the specified algorithm
///
/// - Parameters:
///   - algorithm: The algorithm to use (``KeypairAlgorithm/secp256k1`` or ``KeypairAlgorithm/ed25519``)
///   - privateKeyBytes: Optional private key bytes to use instead of generating new ones
/// - Returns: A ``Keypair`` containing the generated public and private keys
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the algorithm is not supported
public func generateKeypair(
    algorithm: KeypairAlgorithm,
    privateKeyBytes: Data? = nil
) async throws -> Keypair {
    switch algorithm {
    case .ed25519:
        return try await generateEd25519Keypair(privateKeyBytes: privateKeyBytes)
    case .secp256k1:
        return try await generateSecp256k1Keypair(privateKeyBytes: privateKeyBytes)
    }
}

/// Convert a key pair to JWK (JSON Web Key) format
///
/// - Parameter keypair: The ``Keypair`` to convert
/// - Returns: A ``JWK.PrivateKey`` containing the JWK representation
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the key pair's algorithm is not supported
public func keypairToJwk(_ keypair: Keypair) throws -> JWK.PrivateKey {
    return try JWK.keypairToJwk(keypair)
}

/// Convert a JWK (JSON Web Key) to a key pair
///
/// - Parameter jwk: A ``JWK.PrivateKey`` containing the JWK representation
/// - Returns: A ``Keypair`` containing the public and private keys
/// - Throws:
///   - ``KeyError/invalidFormat`` if the JWK format is invalid
///   - ``KeyError/unsupportedAlgorithm`` if the JWK's algorithm is not supported
public func jwkToKeypair(_ jwk: JWK.PrivateKey) throws -> Keypair {
    return try JWK.jwkToKeypair(jwk)
}

/// Encode a public key in the specified format
///
/// - Parameters:
///   - publicKey: The public key data to encode
///   - algorithm: The algorithm used to generate the key pair
///   - encoding: The desired encoding format (``PublicKeyEncoding/hex``, ``PublicKeyEncoding/jwk``, etc.)
/// - Returns: The encoded public key in the specified format
/// - Throws: ``KeyError/unsupportedAlgorithm`` if the encoding format is not supported
public func encodePublicKey<T>(
    _ publicKey: Data,
    algorithm: KeypairAlgorithm,
    encoding: PublicKeyEncoding
) throws -> T {
    switch encoding {
    case .hex:
        return try Hex.encodePublicKey(publicKey, algorithm: algorithm) as! T
    case .jwk:
        return try JWK.encodePublicKey(publicKey, algorithm: algorithm) as! T
    case .multibase:
        return try Multibase.encodePublicKey(publicKey, algorithm: algorithm) as! T
    case .base58:
        return try Base58.encodePublicKey(publicKey, algorithm: algorithm) as! T
    }
}

/// Decode a public key from the specified format
///
/// - Parameters:
///   - string: The encoded public key string
///   - algorithm: The algorithm used to generate the key pair
///   - encoding: The encoding format used (``PublicKeyEncoding/hex``, ``PublicKeyEncoding/jwk``, etc.)
/// - Returns: The decoded public key as ``Data``
/// - Throws:
///   - ``KeyError/invalidFormat`` if the encoded string is invalid
///   - ``KeyError/unsupportedAlgorithm`` if the encoding format is not supported
public func decodePublicKey(
    _ string: String,
    algorithm: KeypairAlgorithm,
    encoding: PublicKeyEncoding
) throws -> Data {
    switch encoding {
    case .hex:
        return try Hex.decodePublicKey(string, algorithm: algorithm)
    case .jwk:
        return try JWK.decodePublicKey(string, algorithm: algorithm)
    case .multibase:
        return try Multibase.decodePublicKey(string, algorithm: algorithm)
    case .base58:
        return try Base58.decodePublicKey(string, algorithm: algorithm)
    }
}

/// Check if a string is a valid public key in the specified format
///
/// - Parameters:
///   - string: The string to validate
///   - algorithm: The algorithm used to generate the key pair
///   - encoding: The encoding format to validate against
/// - Returns: `true` if the string is a valid public key in the specified format
public func isValidPublicKey(
    _ string: String,
    algorithm: KeypairAlgorithm,
    encoding: PublicKeyEncoding
) -> Bool {
    switch encoding {
    case .hex:
        return Hex.isValidPublicKey(string, algorithm: algorithm)
    case .jwk:
        return JWK.isValidPublicKey(string, algorithm: algorithm)
    case .multibase:
        return Multibase.isValidPublicKey(string, algorithm: algorithm)
    case .base58:
        return Base58.isValidPublicKey(string, algorithm: algorithm)
    }
}
