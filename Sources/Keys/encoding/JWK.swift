import Foundation

/// JWK (JSON Web Key) types and encoding implementation
public enum JWK: Encoding, PublicKeyEncoder {
    public typealias PublicKeyType = PublicKey

    /// JWK for Ed25519 public key
    public struct Ed25519PublicKey: Codable {
        public let kty: String = "OKP"
        public let crv: String = "Ed25519"
        public let x: String  // base64url encoded public key

        public init(x: String) {
            self.x = x
        }
    }

    /// JWK for secp256k1 public key
    public struct Secp256k1PublicKey: Codable {
        public let kty: String = "EC"
        public let crv: String = "secp256k1"
        public let x: String  // base64url encoded x-coordinate
        public let y: String  // base64url encoded y-coordinate

        public init(x: String, y: String) {
            self.x = x
            self.y = y
        }
    }

    /// Union type for public key JWKs
    public enum PublicKey: Codable {
        case ed25519(Ed25519PublicKey)
        case secp256k1(Secp256k1PublicKey)

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let dict = try container.decode([String: String].self)

            guard let kty = dict["kty"],
                  let crv = dict["crv"] else {
                throw EncodingError.invalidFormat
            }

            switch (kty, crv) {
            case ("OKP", "Ed25519"):
                guard let x = dict["x"] else {
                    throw EncodingError.invalidFormat
                }
                self = .ed25519(Ed25519PublicKey(x: x))

            case ("EC", "secp256k1"):
                guard let x = dict["x"],
                      let y = dict["y"] else {
                    throw EncodingError.invalidFormat
                }
                self = .secp256k1(Secp256k1PublicKey(x: x, y: y))

            default:
                throw EncodingError.unsupportedAlgorithm
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .ed25519(let key):
                try container.encode(key)
            case .secp256k1(let key):
                try container.encode(key)
            }
        }
    }

    /// Private key JWK (extends public key with private key data)
    public struct PrivateKey: Codable {
        public let publicKey: PublicKey
        public let d: String  // base64url encoded private key

        public init(publicKey: PublicKey, d: String) {
            self.publicKey = publicKey
            self.d = d
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let dict = try container.decode([String: String].self)

            guard let d = dict["d"] else {
                throw EncodingError.invalidFormat
            }

            // Decode the public key part
            let publicKey = try PublicKey(from: decoder)
            self.publicKey = publicKey
            self.d = d
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            var dict = [String: String]()

            // Encode the public key part
            switch publicKey {
            case .ed25519(let key):
                dict["kty"] = key.kty
                dict["crv"] = key.crv
                dict["x"] = key.x
            case .secp256k1(let key):
                dict["kty"] = key.kty
                dict["crv"] = key.crv
                dict["x"] = key.x
                dict["y"] = key.y
            }

            // Add the private key
            dict["d"] = d

            try container.encode(dict)
        }
    }

    /// Encode data to a JWK string
    public static func encode(_ data: Data) throws -> String {
        // For raw data, we'll encode it as a base64url string
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode a JWK string to data
    public static func decode(_ string: String) throws -> Data {
        // For raw data, we'll decode from base64url
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

    /// Check if a string is valid JWK
    public static func isValid(_ string: String) -> Bool {
        do {
            let data = try decode(string)
            return !data.isEmpty
        } catch {
            return false
        }
    }

    /// Encode a public key to JWK
    public static func encodePublicKey(_ publicKey: Data, algorithm: KeypairAlgorithm) throws -> PublicKey {
        switch algorithm {
        case .ed25519:
            return .ed25519(Ed25519PublicKey(x: try encode(publicKey)))

        case .secp256k1:
            guard publicKey.count == 33 else {
                throw EncodingError.invalidLength
            }
            // Skip the first byte (0x04) and split into x and y coordinates
            let xBytes = publicKey[1..<33]
            let yBytes = publicKey[33...]
            return .secp256k1(Secp256k1PublicKey(
                x: try encode(Data(xBytes)),
                y: try encode(Data(yBytes))
            ))
        }
    }

    /// Decode a public key from JWK
    public static func decodePublicKey(_ string: String, algorithm: KeypairAlgorithm) throws -> Data {
        guard let jsonData = string.data(using: .utf8) else {
            throw EncodingError.invalidFormat
        }

        let jwk = try JSONDecoder().decode(PublicKey.self, from: jsonData)

        switch (jwk, algorithm) {
        case (.ed25519(let key), .ed25519):
            return try decode(key.x)

        case (.secp256k1(let key), .secp256k1):
            let xBytes = try decode(key.x)
            let yBytes = try decode(key.y)
            var publicKey = Data([0x04])  // Add the prefix byte
            publicKey.append(xBytes)
            publicKey.append(yBytes)
            return publicKey

        default:
            throw EncodingError.unsupportedAlgorithm
        }
    }

    /// Check if a string is a valid public key JWK
    public static func isValidPublicKey(_ string: String, algorithm: KeypairAlgorithm) -> Bool {
        do {
            guard let jsonData = string.data(using: .utf8) else {
                return false
            }

            let jwk = try JSONDecoder().decode(PublicKey.self, from: jsonData)

            switch (jwk, algorithm) {
            case (.ed25519, .ed25519):
                return true
            case (.secp256k1, .secp256k1):
                return true
            default:
                return false
            }
        } catch {
            return false
        }
    }

    /// Convert a keypair to a private key JWK
    public static func keypairToJwk(_ keypair: Keypair) throws -> PrivateKey {
        let publicKey = try encodePublicKey(keypair.publicKey, algorithm: keypair.algorithm)
        return PrivateKey(publicKey: publicKey, d: try encode(keypair.privateKey))
    }

    /// Convert a private key JWK to a keypair
    public static func jwkToKeypair(_ jwk: PrivateKey) throws -> Keypair {
        let publicKey: Data
        let algorithm: KeypairAlgorithm

        switch jwk.publicKey {
        case .ed25519(let key):
            publicKey = try decode(key.x)
            algorithm = .ed25519
        case .secp256k1(let key):
            let xBytes = try decode(key.x)
            let yBytes = try decode(key.y)
            var fullKey = Data([0x04])  // Add the prefix byte
            fullKey.append(xBytes)
            fullKey.append(yBytes)
            publicKey = fullKey
            algorithm = .secp256k1
        }

        let privateKey = try decode(jwk.d)
        return Keypair(publicKey: publicKey, privateKey: privateKey, algorithm: algorithm)
    }
}
