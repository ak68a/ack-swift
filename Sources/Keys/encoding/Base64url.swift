import Foundation

/// Base64url encoding implementation
///
/// This implementation provides functions for encoding and decoding data to/from Base64url strings.
/// Base64url is a URL-safe variant of Base64 that uses '-' and '_' instead of '+' and '/',
/// and omits padding characters ('=').
///
/// # Examples
///
/// ```swift
/// // Basic encoding and decoding
/// let bytes = Data([1, 2, 3, 4])
/// let base64url = try Base64url.encode(bytes)  // "AQIDBA"
/// let decoded = try Base64url.decode(base64url)  // Data([1, 2, 3, 4])
///
/// // Empty data
/// let empty = try Base64url.encode(Data())  // ""
/// let decodedEmpty = try Base64url.decode("")  // Data()
///
/// // Validation
/// Base64url.isValid("AQIDBA")     // true
/// Base64url.isValid("AQIDBA==")   // false (contains padding)
/// Base64url.isValid("AQIDB+")     // false (contains '+')
/// ```
public enum Base64url: Encoding, PublicKeyEncoder {
    public typealias PublicKeyType = String

    // Base64url alphabet (URL-safe)
    private static let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    /// Encode data to a Base64url string
    ///
    /// Converts binary data to a Base64url string using URL-safe characters.
    /// The output does not include padding characters ('=').
    ///
    /// - Parameter data: The data to encode
    /// - Returns: A Base64url string without padding
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// // Basic encoding
    /// let bytes = Data([1, 2, 3, 4])
    /// let base64url = try Base64url.encode(bytes)  // "AQIDBA"
    ///
    /// // Empty data
    /// let empty = try Base64url.encode(Data())  // ""
    ///
    /// // All zeros
    /// let zeros = try Base64url.encode(Data(repeating: 0, count: 4))  // "AAAAAA"
    ///
    /// // Longer data
    /// let longData = Data([1, 2, 3, 4, 5, 6, 7, 8])
    /// let longEncoded = try Base64url.encode(longData)  // "AQIDBAUGBwg"
    /// ```
    public static func encode(_ data: Data) throws -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode a Base64url string to data
    ///
    /// Converts a Base64url string back to binary data.
    /// The input should not contain padding characters ('=').
    ///
    /// - Parameter string: The Base64url string to decode
    /// - Returns: The decoded data
    /// - Throws: ``EncodingError/invalidCharacter`` if the string contains invalid Base64url characters
    ///
    /// # Example
    /// ```swift
    /// // Basic decoding
    /// let base64url = "AQIDBA"
    /// let bytes = try Base64url.decode(base64url)  // Data([1, 2, 3, 4])
    ///
    /// // Empty string
    /// let empty = try Base64url.decode("")  // Data()
    ///
    /// // Invalid input
    /// try Base64url.decode("AQIDBA==")  // throws EncodingError.invalidCharacter (contains padding)
    /// try Base64url.decode("AQIDB+")    // throws EncodingError.invalidCharacter (contains '+')
    /// try Base64url.decode("AQIDB/")    // throws EncodingError.invalidCharacter (contains '/')
    /// ```
    public static func decode(_ string: String) throws -> Data {
        let base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let padding = String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64 + padding) else {
            throw EncodingError.invalidFormat
        }

        return data
    }

    /// Check if a string is valid Base64url
    ///
    /// Validates that a string contains only valid Base64url characters.
    /// The string should not contain padding characters ('=').
    ///
    /// - Parameter string: The string to validate
    /// - Returns: `true` if the string is valid Base64url, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid Base64url strings
    /// Base64url.isValid("AQIDBA")     // true
    /// Base64url.isValid("")           // true
    /// Base64url.isValid("-_")         // true
    ///
    /// // Invalid Base64url strings
    /// Base64url.isValid("AQIDBA==")   // false (contains padding)
    /// Base64url.isValid("AQIDB+")     // false (contains '+')
    /// Base64url.isValid("AQIDB/")     // false (contains '/')
    /// Base64url.isValid("AQIDB ")     // false (contains space)
    /// ```
    public static func isValid(_ string: String) -> Bool {
        do {
            let data = try decode(string)
            return !data.isEmpty
        } catch {
            return false
        }
    }

    /// Encode a public key to Base64url
    ///
    /// Encodes a public key to a Base64url string, validating the key length based on the algorithm.
    /// The output does not include padding characters ('=').
    ///
    /// - Parameters:
    ///   - publicKey: The public key data to encode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: A Base64url string representation of the public key
    /// - Throws: ``EncodingError/invalidLength`` if the public key length is invalid for the algorithm
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let ed25519Key = Data([/* 32 bytes */])
    /// let encoded = try Base64url.encodePublicKey(ed25519Key, algorithm: .ed25519)  // "AQID..."
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let secpKey = Data([/* 33 or 65 bytes */])
    /// let encoded2 = try Base64url.encodePublicKey(secpKey, algorithm: .secp256k1)  // "AQID..."
    ///
    /// // Invalid length
    /// let invalidKey = Data([1, 2, 3])
    /// try Base64url.encodePublicKey(invalidKey, algorithm: .ed25519)  // throws EncodingError.invalidLength
    /// ```
    public static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> String {
        // Validate key length based on algorithm
        switch algorithm {
        case .ed25519:
            guard publicKey.count == 32 else {
                throw EncodingError.invalidLength
            }
        case .secp256k1:
            guard publicKey.count == 33 || publicKey.count == 65 else {
                throw EncodingError.invalidLength
            }
        }

        // Encode using base64url
        return try encode(publicKey)
    }

    /// Decode a public key from Base64url
    ///
    /// Decodes a Base64url string to a public key, validating the key length based on the algorithm.
    /// The input should not contain padding characters ('=').
    ///
    /// - Parameters:
    ///   - string: The Base64url string to decode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: The decoded public key data
    /// - Throws:
    ///   - ``EncodingError/invalidLength`` if the decoded data length is invalid for the algorithm
    ///   - ``EncodingError/invalidCharacter`` if the string contains invalid Base64url characters
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let base64url = "AQID..." // 32 bytes encoded
    /// let key = try Base64url.decodePublicKey(base64url, algorithm: .ed25519)  // Data([...])
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let base64url2 = "AQID..." // 33 or 65 bytes encoded
    /// let key2 = try Base64url.decodePublicKey(base64url2, algorithm: .secp256k1)  // Data([...])
    ///
    /// // Invalid length
    /// let invalidLength = "AQID"
    /// try Base64url.decodePublicKey(invalidLength, algorithm: .ed25519)  // throws EncodingError.invalidLength
    ///
    /// // Invalid characters
    /// let invalidChars = "AQIDBA=="
    /// try Base64url.decodePublicKey(invalidChars, algorithm: .ed25519)  // throws EncodingError.invalidCharacter
    /// ```
    public static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data {
        // First decode the base64url string
        let decoded = try decode(string)

        // Validate key length based on algorithm
        switch algorithm {
        case .ed25519:
            guard decoded.count == 32 else {
                throw EncodingError.invalidLength
            }
        case .secp256k1:
            guard decoded.count == 33 || decoded.count == 65 else {
                throw EncodingError.invalidLength
            }
        }

        return decoded
    }

    /// Check if a string is a valid public key in Base64url
    ///
    /// Validates that a string is valid Base64url and has the correct length for the specified algorithm.
    /// The input should not contain padding characters ('=').
    ///
    /// - Parameters:
    ///   - string: The string to validate
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: `true` if the string is a valid public key in Base64url, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid Ed25519 public key (32 bytes)
    /// let validEd25519 = "AQID..." // 32 bytes encoded
    /// Base64url.isValidPublicKey(validEd25519, algorithm: .ed25519)  // true
    ///
    /// // Valid secp256k1 public key (65 bytes)
    /// let validSecp = "AQID..." // 65 bytes encoded
    /// Base64url.isValidPublicKey(validSecp, algorithm: .secp256k1)  // true
    ///
    /// // Invalid length
    /// let invalidLength = "AQID"
    /// Base64url.isValidPublicKey(invalidLength, algorithm: .ed25519)  // false
    ///
    /// // Invalid characters
    /// let invalidChars = "AQIDBA=="
    /// Base64url.isValidPublicKey(invalidChars, algorithm: .ed25519)  // false
    ///
    /// // Wrong algorithm
    /// let wrongAlgo = "AQID..." // 32 bytes encoded
    /// Base64url.isValidPublicKey(wrongAlgo, algorithm: .secp256k1)  // false
    /// ```
    public static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool {
        do {
            let decoded = try decode(string)
            switch algorithm {
            case .ed25519:
                return decoded.count == 32
            case .secp256k1:
                return decoded.count == 33 || decoded.count == 65
            }
        } catch {
            return false
        }
    }
}

// MARK: - Convenience Extensions

extension Data {
    /// Convert data to a base64url string
    public var base64urlEncoded: String {
        return (try? Base64url.encode(self)) ?? ""
    }
}

extension String {
    /// Convert a base64url string to data
    public var base64urlDecoded: Data? {
        return try? Base64url.decode(self)
    }

    /// Check if a string is valid base64url
    public var isValidBase64url: Bool {
        return Base64url.isValid(self)
    }
}
