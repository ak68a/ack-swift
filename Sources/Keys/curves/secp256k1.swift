import Foundation
import Crypto
import P256K
import BigInt

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
    do {
        let _ = try P256K.Context.create()
        let seckey = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
        let signature = try seckey.signature(for: message)
        let sigData = signature.dataRepresentation

        // Basic validation that P256K might not do
        guard sigData.count == 64 else {
            throw KeyError.invalidFormat
        }

        // Split into r and s components for basic validation
        let r = sigData.prefix(32)
        let s = sigData.suffix(32)

        // Ensure both components are non-zero
        guard !r.allSatisfy({ $0 == 0 }) && !s.allSatisfy({ $0 == 0 }) else {
            throw KeyError.invalidFormat
        }

        return sigData
    } catch {
        // Convert P256K errors to KeyError.invalidKeyData
        throw KeyError.invalidKeyData
    }
}

/// Check if a signature is in Ed25519 format
/// Ed25519 signatures are 64 bytes long and consist of two 32-byte components (R and S)
/// - Parameter signature: The signature to check
/// - Returns: True if the signature appears to be in Ed25519 format
///
/// Note: This function is currently disabled but kept for future cross-algorithm validation
private func isEd25519Signature(_ signature: Data) -> Bool {
    return false
}

/// Verify a signature using a secp256k1 public key
public func verifySecp256k1(signature: Data, message: Data, publicKey: Data) throws -> Bool {
    // Validate signature length first - this should throw invalidFormat
    guard signature.count == 64 else {
        throw KeyError.invalidFormat
    }

    do {
        let _ = try P256K.Context.create()

        // Basic validation of public key format
        let format: P256K.Format
        switch publicKey.count {
        case 33:
            // Compressed format (33 bytes)
            guard publicKey[0] == 0x02 || publicKey[0] == 0x03 else {
                throw KeyError.invalidKeyData
            }
            format = .compressed
        case 65:
            // Uncompressed format (65 bytes)
            guard publicKey[0] == 0x04 else {
                throw KeyError.invalidKeyData
            }
            format = .uncompressed
        default:
            throw KeyError.invalidKeyData
        }

        // Basic validation of signature components
        let r = signature.prefix(32)
        let s = signature.suffix(32)
        guard !r.allSatisfy({ $0 == 0 }) && !s.allSatisfy({ $0 == 0 }) else {
            return false
        }

        // TODO: Uncomment for cross-algorithm validation
        // Check if this is an Ed25519 signature
        // if isEd25519Signature(signature) {
        //     return false  // Reject Ed25519 signatures when verifying secp256k1
        // }

        // Let P256K handle the cryptographic verification
        let pubkey = try P256K.Signing.PublicKey(dataRepresentation: publicKey, format: format)
        let sig = try P256K.Signing.ECDSASignature(dataRepresentation: signature)
        return pubkey.isValidSignature(sig, for: message)
    } catch {
        // Convert P256K errors to KeyError.invalidKeyData
        throw KeyError.invalidKeyData
    }
}
