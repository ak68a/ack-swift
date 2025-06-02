import Foundation
import BigInt

/// Base58 encoding implementation
///
/// This implementation provides functions for encoding and decoding data to/from Base58 strings.
/// It uses the Bitcoin-style Base58 alphabet which excludes similar-looking characters (0, O, I, l).
///
/// # Examples
///
/// ```swift
/// // Encoding bytes to Base58
/// let bytes = Data([1, 2, 3, 4])
/// let base58 = try Base58.encode(bytes)  // "2VfUX"
///
/// // Decoding Base58 to bytes
/// let base58String = "2VfUX"
/// let decoded = try Base58.decode(base58String)  // Data([1, 2, 3, 4])
///
/// // Validating Base58 strings
/// Base58.isValid("2VfUX")     // true
/// Base58.isValid("2VfUX0")    // false (contains '0')
/// Base58.isValid("2VfUXO")    // false (contains 'O')
/// ```
public enum Base58: Encoding, PublicKeyEncoder {
    public typealias PublicKeyType = String

    // Base58 alphabet (Bitcoin style)
    private static let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private static let base = BigUInt(alphabet.count)

    /// Encode data to a Base58 string
    ///
    /// Converts binary data to a Base58 string using the Bitcoin-style alphabet.
    /// Leading zero bytes are encoded as leading '1' characters.
    ///
    /// - Parameter data: The data to encode
    /// - Returns: A Base58 string
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// let bytes = Data([1, 2, 3, 4])
    /// let base58 = try Base58.encode(bytes)  // "2VfUX"
    /// ```
    public static func encode(_ data: Data) throws -> String {
        guard !data.isEmpty else { return "" }

        // Convert to BigUInt for easier base conversion
        var value = BigUInt(0)
        for byte in data {
            value = (value << 8) | BigUInt(byte)
        }

        // Convert to Base58
        var result = ""
        while value > 0 {
            let (quotient, remainder) = value.quotientAndRemainder(dividingBy: base)
            value = quotient
            result.insert(alphabet[alphabet.index(alphabet.startIndex, offsetBy: Int(remainder))], at: result.startIndex)
        }

        // Add leading '1's for each leading zero byte
        for byte in data {
            if byte == 0 {
                result.insert("1", at: result.startIndex)
            } else {
                break
            }
        }

        return result
    }

    /// Decode a Base58 string to data
    ///
    /// Converts a Base58 string back to binary data.
    /// Leading '1' characters are decoded as leading zero bytes.
    ///
    /// - Parameter string: The Base58 string to decode
    /// - Returns: The decoded data
    /// - Throws: ``EncodingError/invalidCharacter`` if the string contains invalid Base58 characters
    ///
    /// # Example
    /// ```swift
    /// let base58String = "2VfUX"
    /// let bytes = try Base58.decode(base58String)  // Data([1, 2, 3, 4])
    /// ```
    public static func decode(_ string: String) throws -> Data {
        guard !string.isEmpty else { return Data() }

        // Convert from Base58 to BigUInt
        var value = BigUInt(0)
        for char in string {
            guard let digit = alphabet.firstIndex(of: char) else {
                throw EncodingError.invalidCharacter
            }
            value = (value * base) + BigUInt(alphabet.distance(from: alphabet.startIndex, to: digit))
        }

        // Convert to bytes
        var bytes = [UInt8]()
        var temp = value
        while temp > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: temp & 0xFF), at: 0)
            temp >>= 8
        }

        // Add leading zeros for each leading '1'
        for char in string {
            if char == "1" {
                bytes.insert(0, at: 0)
            } else {
                break
            }
        }

        return Data(bytes)
    }

    /// Check if a string is valid Base58
    ///
    /// Validates that a string contains only valid Base58 characters.
    ///
    /// - Parameter string: The string to validate
    /// - Returns: `true` if the string is valid Base58, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// Base58.isValid("2VfUX")     // true
    /// Base58.isValid("2VfUX0")    // false (contains '0')
    /// Base58.isValid("2VfUXO")    // false (contains 'O')
    /// ```
    public static func isValid(_ string: String) -> Bool {
        guard !string.isEmpty else { return true }
        return string.allSatisfy { alphabet.contains($0) }
    }

    /// Encode a public key to Base58
    ///
    /// Encodes a public key to a Base58 string, validating the key length based on the algorithm.
    ///
    /// - Parameters:
    ///   - publicKey: The public key data to encode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: A Base58 string representation of the public key
    /// - Throws: ``EncodingError/unsupportedAlgorithm`` if the public key length is invalid for the algorithm
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let ed25519Key = Data([/* 32 bytes */])
    /// let encoded = try Base58.encodePublicKey(ed25519Key, algorithm: .ed25519)  // "2VfUX..."
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let secpKey = Data([/* 33 or 65 bytes */])
    /// let encoded2 = try Base58.encodePublicKey(secpKey, algorithm: .secp256k1)  // "2VfUX..."
    /// ```
    public static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> String {
        // Validate key length based on algorithm
        switch algorithm {
        case .ed25519:
            guard publicKey.count == 32 else {
                throw EncodingError.unsupportedAlgorithm
            }
        case .secp256k1:
            guard publicKey.count == 33 || publicKey.count == 65 else {
                throw EncodingError.unsupportedAlgorithm
            }
        }

        // For public keys, we might want to add a prefix or checksum
        // This is a simple implementation that just encodes the raw bytes
        return try encode(publicKey)
    }

    /// Decode a public key from Base58
    ///
    /// Decodes a Base58 string to a public key, validating the key length based on the algorithm.
    ///
    /// - Parameters:
    ///   - string: The Base58 string to decode
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: The decoded public key data
    /// - Throws: ``EncodingError/unsupportedAlgorithm`` if the decoded data length is invalid for the algorithm
    ///   - ``EncodingError/invalidCharacter`` if the string contains invalid Base58 characters
    ///
    /// # Example
    /// ```swift
    /// // Ed25519 public key (32 bytes)
    /// let base58String = "2VfUX..." // 32 bytes encoded
    /// let key = try Base58.decodePublicKey(base58String, algorithm: .ed25519)  // Data([...])
    ///
    /// // secp256k1 public key (33 or 65 bytes)
    /// let base58String2 = "2VfUX..." // 33 or 65 bytes encoded
    /// let key2 = try Base58.decodePublicKey(base58String2, algorithm: .secp256k1)  // Data([...])
    /// ```
    public static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data {
        let data = try decode(string)

        // Verify length based on algorithm
        switch algorithm {
        case .ed25519:
            guard data.count == 32 else {
                throw EncodingError.unsupportedAlgorithm
            }
        case .secp256k1:
            guard data.count == 33 || data.count == 65 else {
                throw EncodingError.unsupportedAlgorithm
            }
        }

        return data
    }

    /// Check if a string is a valid public key in Base58
    ///
    /// Validates that a string is valid Base58 and has the correct length for the specified algorithm.
    ///
    /// - Parameters:
    ///   - string: The string to validate
    ///   - algorithm: The algorithm used to generate the key pair
    /// - Returns: `true` if the string is a valid public key in Base58, `false` otherwise
    ///
    /// # Example
    /// ```swift
    /// // Valid Ed25519 public key (32 bytes)
    /// let validEd25519 = "2VfUX..." // 32 bytes encoded
    /// Base58.isValidPublicKey(validEd25519, algorithm: .ed25519)  // true
    ///
    /// // Valid secp256k1 public key (65 bytes)
    /// let validSecp = "2VfUX..." // 65 bytes encoded
    /// Base58.isValidPublicKey(validSecp, algorithm: .secp256k1)  // true
    ///
    /// // Invalid length
    /// let invalid = "2VfUX"
    /// Base58.isValidPublicKey(invalid, algorithm: .ed25519)  // false
    /// ```
    public static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool {
        // First check if it's valid Base58
        guard isValid(string) else { return false }

        // Then check length based on algorithm
        let data = try? decode(string)
        guard let decoded = data else { return false }

        switch algorithm {
        case .ed25519:
            return decoded.count == 32
        case .secp256k1:
            return decoded.count == 33 || decoded.count == 65
        }
    }
}

// MARK: - Convenience Extensions

extension Data {
    /// Convert data to a base58 string
    ///
    /// Converts binary data to a base58 string using the Bitcoin-style alphabet.
    /// Leading zero bytes are encoded as leading '1' characters.
    ///
    /// - Returns: A base58 string
    /// - Throws: Never
    ///
    /// # Example
    /// ```swift
    /// let data = Data([1, 2, 3, 4])
    /// let base58 = try data.toBase58()  // "2VfUX"
    /// ```
    public func toBase58() throws -> String {
        return try Base58.encode(self)
    }
}

extension String {
    /// Convert a base58 string to data
    ///
    /// Converts a base58 string back to binary data.
    /// Leading '1' characters are decoded as leading zero bytes.
    ///
    /// - Returns: The decoded data
    /// - Throws: ``EncodingError/invalidCharacter`` if the string contains invalid base58 characters
    ///
    /// # Example
    /// ```swift
    /// let base58 = "2VfUX"
    /// let data = try base58.fromBase58()  // Data([1, 2, 3, 4])
    /// ```
    public func fromBase58() throws -> Data {
        return try Base58.decode(self)
    }

    /// Check if a string is valid base58
    ///
    /// Validates that a string contains only valid base58 characters.
    ///
    /// # Example
    /// ```swift
    /// "2VfUX".isValidBase58     // true
    /// "2VfUX0".isValidBase58    // false (contains '0')
    /// "2VfUXO".isValidBase58    // false (contains 'O')
    /// ```
    public var isValidBase58: Bool {
        return Base58.isValid(self)
    }
}
