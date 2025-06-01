import Foundation

/// Protocol for encoding/decoding data in various formats
public protocol Encoding {
    /// Encode data to a string representation
    static func encode(_ data: Data) throws -> String

    /// Decode a string representation back to data
    static func decode(_ string: String) throws -> Data

    /// Check if a string is valid for this encoding
    static func isValid(_ string: String) -> Bool
}

/// Protocol for encoding public keys in various formats
public protocol PublicKeyEncoder {
    /// The type returned by encodePublicKey for this encoding
    associatedtype PublicKeyType

    /// Encode a public key to this encoding's representation
    static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> PublicKeyType

    /// Decode a public key from this encoding's representation
    static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data

    /// Check if a string is a valid public key in this encoding
    static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool
}

/// Common encoding errors
public enum EncodingError: Error {
    case invalidFormat
    case invalidLength
    case invalidCharacter
    case unsupportedAlgorithm
    case invalidChecksum
}
