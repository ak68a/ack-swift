import Foundation

/// Supported key pair algorithms
public enum KeypairAlgorithm: String {
    case secp256k1 = "secp256k1"
    case ed25519 = "Ed25519"
}

/// Supported public key encoding formats
public enum PublicKeyEncoding: String {
    case hex
    case jwk
    case multibase
    case base58
}

/// Represents a key pair with public and private keys
public struct Keypair {
    public let publicKey: Data
    public let privateKey: Data
    public let algorithm: KeypairAlgorithm

    public init(publicKey: Data, privateKey: Data, algorithm: KeypairAlgorithm) {
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.algorithm = algorithm
    }
}

/// Errors that can occur during key operations
public enum KeyError: Error {
    case invalidKeyData
    case unsupportedAlgorithm
    case exportFailed
    case importFailed
    case invalidFormat
    case invalidEncoding
}
