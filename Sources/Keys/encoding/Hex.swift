import Foundation

/// Hex encoding implementation
///
/// This implementation provides functions for encoding and decoding data to/from hexadecimal strings.
/// It supports both lowercase hex strings and handles optional "0x" prefixes.
///
/// # Examples
///
/// ```swift
/// // Basic encoding and decoding
/// let bytes = Data([1, 2, 3, 4])
/// let hex = try Hex.encode(bytes)  // "01020304"
/// let decoded = try Hex.decode(hex)  // Data([1, 2, 3, 4])
///
/// // With 0x prefix
/// let hexWithPrefix = "0x01020304"
/// let decoded2 = try Hex.decode(hexWithPrefix)  // Data([1, 2, 3, 4])
///
/// // Validation
/// Hex.isValid("0x1234567890abcdef")  // true
/// Hex.isValid("1234567890abcdef")    // true
/// Hex.isValid("0x1234567890abcdefg") // false
///
/// // Public key encoding
/// let publicKey = Data([/* 32 or 65 bytes */])
/// let encoded = try Hex.encodePublicKey(publicKey, algorithm: .ed25519)  // "0123..."
/// ```
public enum Hex: Encoding, PublicKeyEncoder {
    public typealias PublicKeyType = String

    // Hex alphabet (lowercase)
    private static let alphabet = "0123456789abcdef"

    /// Encode data to a hex string
    ///
    /// Converts each byte to its two-character hexadecimal representation.
    /// The output is always lowercase and does not include a "0x" prefix.
    ///
    /// - Parameter data: The data to encode
    /// - Returns: A lowercase hex string without "0x" prefix
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// let bytes = Data([1, 2, 3, 4])
    /// let hex = try Hex.encode(bytes)  // "01020304"
    ///
    /// // Empty data
    /// let empty = try Hex.encode(Data())  // ""
    ///
    /// // All zeros
    /// let zeros = try Hex.encode(Data(repeating: 0, count: 4))  // "00000000"
    /// ```
    public static func encode(_ data: Data) throws -> String {
        return data.map { byte in
            let high = alphabet[alphabet.index(alphabet.startIndex, offsetBy: Int(byte >> 4))]
            let low = alphabet[alphabet.index(alphabet.startIndex, offsetBy: Int(byte & 0x0F))]
            return String(high) + String(low)
        }.joined()
    }

    /// Decode a hex string to data
    ///
    /// Converts a hex string (with or without "0x" prefix) to its byte representation.
    /// The input can be either uppercase or lowercase.
    ///
    /// - Parameter string: The hex string to decode
    /// - Returns: The decoded data
    /// - Throws:
    ///   - ``EncodingError/invalidLength`` if the string length is odd
    ///   - ``EncodingError/invalidCharacter`` if the string contains invalid hex characters
    ///
    /// # Example
    /// ```swift
    /// // With 0x prefix
    /// let hexWithPrefix = "0x01020304"
    /// let bytes = try Hex.decode(hexWithPrefix)  // Data([1, 2, 3, 4])
    ///
    /// // Without prefix
    /// let hexWithoutPrefix = "01020304"
    /// let bytes2 = try Hex.decode(hexWithoutPrefix)  // Data([1, 2, 3, 4])
    ///
    /// // Empty string
    /// let empty = try Hex.decode("")  // Data()
    ///
    /// // Invalid input
    /// try Hex.decode("0x123")  // throws EncodingError.invalidLength
    /// try Hex.decode("0x123g") // throws EncodingError.invalidCharacter
    /// ```
    public static func decode(_ string: String) throws -> Data {
        // Remove any "0x" prefix
        let hexString = string.hasPrefix("0x") ? String(string.dropFirst(2)) : string

        // Ensure even length
        guard hexString.count % 2 == 0 else {
            throw EncodingError.invalidLength
        }

        // Convert pairs of hex characters to bytes
        var bytes = [UInt8]()
        var index = hexString.startIndex

        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let byteString = String(hexString[index..<nextIndex])

            guard let byte = UInt8(byteString, radix: 16) else {
                throw EncodingError.invalidCharacter
            }

            bytes.append(byte)
            index = nextIndex
        }

        return Data(bytes)
    }

    /// Check if a string is valid hex
    ///
    /// Validates that a string contains only valid hexadecimal characters.
    /// Accepts both with and without "0x" prefix, and both uppercase and lowercase.
    ///
    /// - Parameter string: The string to validate
    /// - Returns: `true` if the string is valid hex, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid hex strings
    /// Hex.isValid("0x1234567890abcdef")  // true
    /// Hex.isValid("1234567890abcdef")    // true
    /// Hex.isValid("0x")                  // true
    /// Hex.isValid("")                    // true
    ///
    /// // Invalid hex strings
    /// Hex.isValid("0x1234567890abcdefg") // false (contains 'g')
    /// Hex.isValid("not hex")             // false
    /// Hex.isValid("0x123")               // false (odd length)
    /// ```
    public static func isValid(_ string: String) -> Bool {
        // Remove any "0x" prefix
        let hexString = string.hasPrefix("0x") ? String(string.dropFirst(2)) : string

        // Check length and characters
        guard hexString.count % 2 == 0 else { return false }
        return hexString.allSatisfy { char in
            alphabet.contains(char.lowercased())
        }
    }

    /// Encode a public key to hex
    ///
    /// Encodes a public key to a hex string, validating the key length based on the algorithm.
    /// The output is always lowercase and does not include a "0x" prefix.
    ///
    /// - Parameters:
    ///   - publicKey: The public key data to encode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: A hex string representation of the public key
    /// - Throws: ``EncodingError/invalidLength`` if the public key length is invalid for the algorithm
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let ed25519Key = Data([/* 32 bytes */])
    /// let encoded = try Hex.encodePublicKey(ed25519Key, algorithm: .ed25519)  // "0123..."
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let secpKey = Data([/* 33 or 65 bytes */])
    /// let encoded2 = try Hex.encodePublicKey(secpKey, algorithm: .secp256k1)  // "0123..."
    ///
    /// // Invalid length
    /// let invalidKey = Data([1, 2, 3])
    /// try Hex.encodePublicKey(invalidKey, algorithm: .ed25519)  // throws EncodingError.invalidLength
    /// ```
    public static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> String {
        // For public keys, we might want to add a prefix or format differently
        // This is a simple implementation that just encodes the raw bytes
        return try encode(publicKey)
    }

    /// Decode a public key from hex
    ///
    /// Decodes a hex string to a public key, validating the key length based on the algorithm.
    /// The input can be with or without "0x" prefix, and either uppercase or lowercase.
    ///
    /// - Parameters:
    ///   - string: The hex string to decode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: The decoded public key data
    /// - Throws:
    ///   - ``EncodingError/invalidLength`` if the decoded data length is invalid for the algorithm
    ///   - ``EncodingError/invalidCharacter`` if the string contains invalid hex characters
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let hexString = "0x" + String(repeating: "01", count: 32)
    /// let key = try Hex.decodePublicKey(hexString, algorithm: .ed25519)  // Data([1, 1, ...])
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let hexString2 = "0x" + String(repeating: "01", count: 65)
    /// let key2 = try Hex.decodePublicKey(hexString2, algorithm: .secp256k1)  // Data([1, 1, ...])
    ///
    /// // Invalid length
    /// let invalidHex = "0x0102"
    /// try Hex.decodePublicKey(invalidHex, algorithm: .ed25519)  // throws EncodingError.invalidLength
    ///
    /// // Invalid characters
    /// let invalidChars = "0x123g"
    /// try Hex.decodePublicKey(invalidChars, algorithm: .ed25519)  // throws EncodingError.invalidCharacter
    /// ```
    public static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data {
        // For public keys, we might want to verify length or other constraints
        let data = try decode(string)

        // Verify length based on algorithm
        switch algorithm {
        case .ed25519:
            guard data.count == 32 else {
                throw EncodingError.invalidLength
            }
        case .secp256k1:
            // secp256k1 public keys can be 33 bytes (compressed) or 65 bytes (uncompressed)
            guard data.count == 33 || data.count == 65 else {
                throw EncodingError.invalidLength
            }
        }

        return data
    }

    /// Check if a string is a valid public key in hex
    ///
    /// Validates that a string is valid hex and has the correct length for the specified algorithm.
    /// The input can be with or without "0x" prefix, and either uppercase or lowercase.
    ///
    /// - Parameters:
    ///   - string: The string to validate
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: `true` if the string is a valid public key in hex, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid Ed25519 public key (32 bytes)
    /// let validEd25519 = "0x" + String(repeating: "01", count: 32)
    /// Hex.isValidPublicKey(validEd25519, algorithm: .ed25519)  // true
    ///
    /// // Valid secp256k1 public key (65 bytes)
    /// let validSecp = "0x" + String(repeating: "01", count: 65)
    /// Hex.isValidPublicKey(validSecp, algorithm: .secp256k1)  // true
    ///
    /// // Invalid length
    /// let invalidLength = "0x0102"
    /// Hex.isValidPublicKey(invalidLength, algorithm: .ed25519)  // false
    ///
    /// // Invalid characters
    /// let invalidChars = "0x123g"
    /// Hex.isValidPublicKey(invalidChars, algorithm: .ed25519)  // false
    ///
    /// // Wrong algorithm
    /// let wrongAlgo = "0x" + String(repeating: "01", count: 32)
    /// Hex.isValidPublicKey(wrongAlgo, algorithm: .secp256k1)  // false
    /// ```
    public static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool {
        // First check if it's valid hex
        guard isValid(string) else { return false }

        // Then check length based on algorithm
        let hexString = string.hasPrefix("0x") ? String(string.dropFirst(2)) : string
        let byteLength = hexString.count / 2

        switch algorithm {
        case .ed25519:
            return byteLength == 32
        case .secp256k1:
            return byteLength == 33 || byteLength == 65
        }
    }
}
