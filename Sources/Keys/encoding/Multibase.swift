import Foundation

/// Supported multibase encodings
///
/// Multibase is a protocol for encoding binary data in various base encodings with a prefix
/// that identifies the encoding used. This makes it easy to identify and decode the data
/// without knowing the encoding in advance.
///
/// # Examples
///
/// ```swift
/// // Different encodings for the same data
/// let data = Data([1, 2, 3, 4])
/// let base58btc = try Multibase.encode(data, encoding: .base58btc)  // "z2VfUX"
/// let base64url = try Multibase.encode(data, encoding: .base64url)  // "uAQIDBA"
/// let base16 = try Multibase.encode(data, encoding: .base16)        // "f01020304"
///
/// // Decoding without knowing the encoding
/// let decoded = try Multibase.decode(base58btc)  // Data([1, 2, 3, 4])
/// let decoded2 = try Multibase.decode(base64url) // Data([1, 2, 3, 4])
/// let decoded3 = try Multibase.decode(base16)    // Data([1, 2, 3, 4])
///
/// // Validation
/// Multibase.isValid("z2VfUX")     // true
/// Multibase.isValid("uAQIDBA")    // true
/// Multibase.isValid("f01020304")  // true
/// Multibase.isValid("invalid")    // false
/// ```
public enum MultibaseEncoding: String {
    case base58btc = "z"  // Bitcoin's base58 (default)
    case base64url = "u"  // URL-safe base64
    case base16 = "f"     // hex
}

/// Multibase encoding implementation
///
/// This implementation provides functions for encoding and decoding data to/from multibase strings.
/// Multibase is a protocol for encoding binary data in various base encodings with a prefix
/// that identifies the encoding used.
///
/// # Examples
///
/// ```swift
/// // Basic encoding and decoding
/// let data = Data([1, 2, 3, 4])
/// let multibase = try Multibase.encode(data)  // "z2VfUX" (defaults to base58btc)
/// let decoded = try Multibase.decode(multibase)  // Data([1, 2, 3, 4])
///
/// // Different encodings
/// let base64url = try Multibase.encode(data, encoding: .base64url)  // "uAQIDBA"
/// let base16 = try Multibase.encode(data, encoding: .base16)        // "f01020304"
///
/// // Empty data
/// let empty = try Multibase.encode(Data())  // "z"
/// let decodedEmpty = try Multibase.decode("z")  // Data()
///
/// // Validation
/// Multibase.isValid("z2VfUX")     // true
/// Multibase.isValid("uAQIDBA")    // true
/// Multibase.isValid("f01020304")  // true
/// Multibase.isValid("invalid")    // false
/// ```
public enum Multibase: Encoding, PublicKeyEncoder {
    public typealias PublicKeyType = String

    /// Encode data to a multibase string
    ///
    /// Converts binary data to a multibase string using the default encoding (base58btc).
    /// The output includes a prefix that identifies the encoding used.
    ///
    /// - Parameter data: The data to encode
    /// - Returns: A multibase string with encoding prefix
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// // Basic encoding (defaults to base58btc)
    /// let data = Data([1, 2, 3, 4])
    /// let multibase = try Multibase.encode(data)  // "z2VfUX"
    ///
    /// // Empty data
    /// let empty = try Multibase.encode(Data())  // "z"
    ///
    /// // All zeros
    /// let zeros = try Multibase.encode(Data(repeating: 0, count: 4))  // "z1111111"
    /// ```
    public static func encode(_ data: Data) throws -> String {
        return try encode(data, encoding: .base58btc)
    }

    /// Encode data to a multibase string with specific encoding
    ///
    /// Converts binary data to a multibase string using the specified encoding.
    /// The output includes a prefix that identifies the encoding used.
    ///
    /// - Parameters:
    ///   - data: The data to encode
    ///   - encoding: The desired encoding (base58btc, base64url, or base16)
    /// - Returns: A multibase string with encoding prefix
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// let data = Data([1, 2, 3, 4])
    ///
    /// // Base58btc encoding
    /// let base58btc = try Multibase.encode(data, encoding: .base58btc)  // "z2VfUX"
    ///
    /// // Base64url encoding
    /// let base64url = try Multibase.encode(data, encoding: .base64url)  // "uAQIDBA"
    ///
    /// // Base16 (hex) encoding
    /// let base16 = try Multibase.encode(data, encoding: .base16)        // "f01020304"
    /// ```
    public static func encode(_ data: Data, encoding: MultibaseEncoding) throws -> String {
        let encoded: String
        switch encoding {
        case .base58btc:
            encoded = try Base58.encode(data)
        case .base64url:
            encoded = try Base64url.encode(data)
        case .base16:
            encoded = try Hex.encode(data)
        }
        return encoding.rawValue + encoded
    }

    /// Decode a multibase string to data
    ///
    /// Converts a multibase string back to binary data, using the encoding specified by the prefix.
    ///
    /// - Parameter string: The multibase string to decode
    /// - Returns: The decoded data
    /// - Throws:
    ///   - ``EncodingError/invalidFormat`` if the string is empty or has an invalid prefix
    ///   - ``EncodingError/unsupportedAlgorithm`` if the encoding prefix is not supported
    ///   - ``EncodingError/invalidCharacter`` if the encoded portion contains invalid characters
    ///
    /// # Example
    /// ```swift
    /// // Base58btc encoded
    /// let base58btc = "z2VfUX"
    /// let decoded = try Multibase.decode(base58btc)  // Data([1, 2, 3, 4])
    ///
    /// // Base64url encoded
    /// let base64url = "uAQIDBA"
    /// let decoded2 = try Multibase.decode(base64url)  // Data([1, 2, 3, 4])
    ///
    /// // Base16 (hex) encoded
    /// let base16 = "f01020304"
    /// let decoded3 = try Multibase.decode(base16)  // Data([1, 2, 3, 4])
    ///
    /// // Empty string
    /// try Multibase.decode("")  // throws EncodingError.invalidFormat
    ///
    /// // Invalid prefix
    /// try Multibase.decode("x123")  // throws EncodingError.unsupportedAlgorithm
    ///
    /// // Invalid characters
    /// try Multibase.decode("z2VfUX+")  // throws EncodingError.invalidCharacter
    /// ```
    public static func decode(_ string: String) throws -> Data {
        guard !string.isEmpty else {
            throw EncodingError.invalidFormat
        }

        let prefix = String(string.prefix(1))
        guard let encoding = MultibaseEncoding(rawValue: prefix) else {
            throw EncodingError.unsupportedAlgorithm
        }

        let encoded = String(string.dropFirst())
        switch encoding {
        case .base58btc:
            return try Base58.decode(encoded)
        case .base64url:
            return try Base64url.decode(encoded)
        case .base16:
            return try Hex.decode(encoded)
        }
    }

    /// Check if a string is valid multibase
    ///
    /// Validates that a string has a valid multibase prefix and that the encoded portion
    /// is valid for the specified encoding.
    ///
    /// - Parameter string: The string to validate
    /// - Returns: `true` if the string is valid multibase, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid multibase strings
    /// Multibase.isValid("z2VfUX")     // true (base58btc)
    /// Multibase.isValid("uAQIDBA")    // true (base64url)
    /// Multibase.isValid("f01020304")  // true (base16)
    /// Multibase.isValid("z")          // true (empty base58btc)
    ///
    /// // Invalid multibase strings
    /// Multibase.isValid("")           // false (empty)
    /// Multibase.isValid("x123")       // false (invalid prefix)
    /// Multibase.isValid("z2VfUX+")    // false (invalid base58btc)
    /// Multibase.isValid("uAQIDBA==")  // false (invalid base64url)
    /// Multibase.isValid("f0102030g")  // false (invalid base16)
    /// ```
    public static func isValid(_ string: String) -> Bool {
        guard !string.isEmpty else { return false }

        let prefix = String(string.prefix(1))
        guard let encoding = MultibaseEncoding(rawValue: prefix) else {
            return false
        }

        let encoded = String(string.dropFirst())
        switch encoding {
        case .base58btc:
            return Base58.isValid(encoded)
        case .base64url:
            return Base64url.isValid(encoded)
        case .base16:
            return Hex.isValid(encoded)
        }
    }

    /// Get the encoding type from a multibase string
    ///
    /// Extracts the encoding type from a multibase string's prefix.
    ///
    /// - Parameter string: The multibase string
    /// - Returns: The encoding type if the prefix is valid, `nil` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid prefixes
    /// Multibase.getEncoding("z2VfUX")     // .base58btc
    /// Multibase.getEncoding("uAQIDBA")    // .base64url
    /// Multibase.getEncoding("f01020304")  // .base16
    ///
    /// // Invalid prefixes
    /// Multibase.getEncoding("")           // nil
    /// Multibase.getEncoding("x123")       // nil
    /// ```
    public static func getEncoding(_ string: String) -> MultibaseEncoding? {
        guard !string.isEmpty else { return nil }
        return MultibaseEncoding(rawValue: String(string.prefix(1)))
    }

    /// Encode a public key to multibase
    ///
    /// Encodes a public key to a multibase string using base58btc encoding (the most common
    /// encoding for public keys in blockchain applications).
    ///
    /// - Parameters:
    ///   - publicKey: The public key data to encode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: A multibase string representation of the public key
    /// - Throws: ``EncodingError/invalidLength`` if the public key length is invalid for the algorithm
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let ed25519Key = Data([/* 32 bytes */])
    /// let encoded = try Multibase.encodePublicKey(ed25519Key, algorithm: .ed25519)  // "z..."
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let secpKey = Data([/* 33 or 65 bytes */])
    /// let encoded2 = try Multibase.encodePublicKey(secpKey, algorithm: .secp256k1)  // "z..."
    ///
    /// // Invalid length
    /// let invalidKey = Data([1, 2, 3])
    /// try Multibase.encodePublicKey(invalidKey, algorithm: .ed25519)  // throws EncodingError.invalidLength
    /// ```
    public static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> String {
        // For public keys, we'll use base58btc by default as it's most commonly used
        // for public key encoding in blockchain applications
        return try encode(publicKey, encoding: .base58btc)
    }

    /// Decode a public key from multibase
    ///
    /// Decodes a multibase string to a public key, validating the key length based on the algorithm.
    ///
    /// - Parameters:
    ///   - string: The multibase string to decode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: The decoded public key data
    /// - Throws:
    ///   - ``EncodingError/invalidFormat`` if the string is empty or has an invalid prefix
    ///   - ``EncodingError/unsupportedAlgorithm`` if the encoding prefix is not supported
    ///   - ``EncodingError/invalidCharacter`` if the encoded portion contains invalid characters
    ///   - ``EncodingError/invalidLength`` if the decoded data length is invalid for the algorithm
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let multibase = "z..." // 32 bytes encoded
    /// let key = try Multibase.decodePublicKey(multibase, algorithm: .ed25519)  // Data([...])
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let multibase2 = "z..." // 33 or 65 bytes encoded
    /// let key2 = try Multibase.decodePublicKey(multibase2, algorithm: .secp256k1)  // Data([...])
    ///
    /// // Invalid length
    /// let invalidLength = "z2VfUX"
    /// try Multibase.decodePublicKey(invalidLength, algorithm: .ed25519)  // throws EncodingError.invalidLength
    ///
    /// // Invalid format
    /// try Multibase.decodePublicKey("", algorithm: .ed25519)  // throws EncodingError.invalidFormat
    /// try Multibase.decodePublicKey("x123", algorithm: .ed25519)  // throws EncodingError.unsupportedAlgorithm
    /// ```
    public static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data {
        let data = try decode(string)

        // Validate the decoded data based on the algorithm
        switch algorithm {
        case .ed25519:
            guard data.count == 32 else {
                throw EncodingError.invalidLength
            }
        case .secp256k1:
            guard data.count == 33 || data.count == 65 else {
                throw EncodingError.invalidLength
            }
        }

        return data
    }

    /// Check if a string is a valid public key multibase
    ///
    /// Validates that a string is valid multibase and has the correct length for the specified algorithm.
    ///
    /// - Parameters:
    ///   - string: The string to validate
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: `true` if the string is a valid public key multibase, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid Ed25519 public key (32 bytes)
    /// let validEd25519 = "z..." // 32 bytes encoded
    /// Multibase.isValidPublicKey(validEd25519, algorithm: .ed25519)  // true
    ///
    /// // Valid secp256k1 public key (65 bytes)
    /// let validSecp = "z..." // 65 bytes encoded
    /// Multibase.isValidPublicKey(validSecp, algorithm: .secp256k1)  // true
    ///
    /// // Invalid length
    /// let invalidLength = "z2VfUX"
    /// Multibase.isValidPublicKey(invalidLength, algorithm: .ed25519)  // false
    ///
    /// // Invalid format
    /// Multibase.isValidPublicKey("", algorithm: .ed25519)  // false
    /// Multibase.isValidPublicKey("x123", algorithm: .ed25519)  // false
    ///
    /// // Wrong algorithm
    /// let wrongAlgo = "z..." // 32 bytes encoded
    /// Multibase.isValidPublicKey(wrongAlgo, algorithm: .secp256k1)  // false
    /// ```
    public static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool {
        do {
            let data = try decode(string)
            switch algorithm {
            case .ed25519:
                return data.count == 32
            case .secp256k1:
                return data.count == 33 || data.count == 65
            }
        } catch {
            return false
        }
    }
}

// MARK: - Convenience Extensions

extension Data {
    /// Convert data to a multibase string
    ///
    /// Converts binary data to a multibase string using the specified encoding.
    /// The output includes a prefix that identifies the encoding used.
    ///
    /// - Parameter encoding: The desired encoding (defaults to base58btc)
    /// - Returns: A multibase string with encoding prefix
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// let data = Data([1, 2, 3, 4])
    ///
    /// // Default encoding (base58btc)
    /// let multibase = try data.toMultibase()  // "z2VfUX"
    ///
    /// // Specific encoding
    /// let base64url = try data.toMultibase(encoding: .base64url)  // "uAQIDBA"
    /// let base16 = try data.toMultibase(encoding: .base16)        // "f01020304"
    /// ```
    public func toMultibase(encoding: MultibaseEncoding = .base58btc) throws -> String {
        return try Multibase.encode(self, encoding: encoding)
    }
}

extension String {
    /// Convert a multibase string to data
    ///
    /// Converts a multibase string back to binary data, using the encoding specified by the prefix.
    ///
    /// - Returns: The decoded data
    /// - Throws:
    ///   - ``EncodingError/invalidFormat`` if the string is empty or has an invalid prefix
    ///   - ``EncodingError/unsupportedAlgorithm`` if the encoding prefix is not supported
    ///   - ``EncodingError/invalidCharacter`` if the encoded portion contains invalid characters
    ///
    /// # Example
    /// ```swift
    /// // Base58btc encoded
    /// let base58btc = "z2VfUX"
    /// let decoded = try base58btc.fromMultibase()  // Data([1, 2, 3, 4])
    ///
    /// // Base64url encoded
    /// let base64url = "uAQIDBA"
    /// let decoded2 = try base64url.fromMultibase()  // Data([1, 2, 3, 4])
    ///
    /// // Base16 (hex) encoded
    /// let base16 = "f01020304"
    /// let decoded3 = try base16.fromMultibase()  // Data([1, 2, 3, 4])
    /// ```
    public func fromMultibase() throws -> Data {
        return try Multibase.decode(self)
    }

    /// Check if a string is valid multibase
    ///
    /// Validates that a string has a valid multibase prefix and that the encoded portion
    /// is valid for the specified encoding.
    ///
    /// # Example
    /// ```swift
    /// // Valid multibase strings
    /// "z2VfUX".isValidMultibase     // true (base58btc)
    /// "uAQIDBA".isValidMultibase    // true (base64url)
    /// "f01020304".isValidMultibase  // true (base16)
    ///
    /// // Invalid multibase strings
    /// "".isValidMultibase           // false (empty)
    /// "x123".isValidMultibase       // false (invalid prefix)
    /// "z2VfUX+".isValidMultibase    // false (invalid base58btc)
    /// ```
    public var isValidMultibase: Bool {
        return Multibase.isValid(self)
    }

    /// Get the multibase encoding of a string
    ///
    /// Extracts the encoding type from a multibase string's prefix.
    ///
    /// # Example
    /// ```swift
    /// // Valid prefixes
    /// "z2VfUX".multibaseEncoding     // .base58btc
    /// "uAQIDBA".multibaseEncoding    // .base64url
    /// "f01020304".multibaseEncoding  // .base16
    ///
    /// // Invalid prefixes
    /// "".multibaseEncoding           // nil
    /// "x123".multibaseEncoding       // nil
    /// ```
    public var multibaseEncoding: MultibaseEncoding? {
        return Multibase.getEncoding(self)
    }
}
