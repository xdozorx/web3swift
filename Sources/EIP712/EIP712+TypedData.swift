// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
import Foundation
import CryptoSwift

/// A struct represents EIP712 type tuple
public struct EIP712Type: Codable {
    let name: String
    let type: String
}

/// A struct represents EIP712 Domain
public struct EIP712Domain: Codable {
    let name: String
    let version: String
    let chainId: Int
    let verifyingContract: String
    let salt: String
}

/// A struct represents EIP712 TypedData
public struct EIP712TypedData: Codable {
    public let types: [String: [EIP712Type]]
    public let primaryType: String
    public let domain: EIP712_JSON
    public let message: EIP712_JSON
}

public enum EIP712TypedDataSignVersion {
    case v3
    case v4
    case latest
}

extension EIP712TypedData {
    /// Type hash for the primaryType of an `EIP712TypedData`
    public var typeHash: Data {
        let data = encodeType(primaryType: primaryType)
        return data.sha3(.keccak256)
    }

    /// Sign-able hash for an `EIP712TypedData` with version specific.
    public func signableHash(version: EIP712TypedDataSignVersion) throws -> Data {
        let data = Data([0x19, 0x01])
        + (try encodeData(data: domain, type: "EIP712Domain", version: version)).sha3(.keccak256)
        + (try encodeData(data: message, type: primaryType, version: version)).sha3(.keccak256)
        return data.sha3(.keccak256)
    }

    /// Recursively finds all the dependencies of a type
    func findDependencies(primaryType: String, dependencies: Set<String> = Set<String>()) -> Set<String> {
        var found = dependencies
        guard !found.contains(primaryType),
            let primaryTypes = types[primaryType] else {
                return found
        }
        found.insert(primaryType)
        for type in primaryTypes {
            findDependencies(primaryType: type.type, dependencies: found)
                .forEach { found.insert($0) }
        }
        return found
    }

    /// Encode a type of struct
    public func encodeType(primaryType: String) -> Data {
        var depSet = findDependencies(primaryType: primaryType)
        depSet.remove(primaryType)
        let sorted = [primaryType] + Array(depSet).sorted()
        let encoded = sorted.map { type in
            let param = types[type]!.map { "\($0.type) \($0.name)" }.joined(separator: ",")
            return "\(type)(\(param))"
        }.joined()
        return encoded.data(using: .utf8) ?? Data()
    }

    /// Encode an instance of struct
    ///
    /// Implemented with `ABIEncoder` and `ABIValue`
    public func encodeData(
        data: EIP712_JSON,
        type: String,
        version: EIP712TypedDataSignVersion = .latest
    ) throws -> Data {
        let encoder = EIP712_ABIEncoder()
        var values: [EIP712_ABIValue] = []
        let typeHash = encodeType(primaryType: type).sha3(.keccak256)
        let typeHashValue = try EIP712_ABIValue(typeHash, type: .bytes(32))
        values.append(typeHashValue)
        if let valueTypes = types[type] {
            try valueTypes.forEach { field in
                switch version {
                case .v3:
                    if isCustomType(rawType: field.type),
                       let json = data[field.name] {
                        let nestEncoded = try encodeData(data: json, type: field.type, version: version)
                        values.append(try EIP712_ABIValue(nestEncoded.sha3(.keccak256), type: .bytes(32)))
                    } else if let value = try makeABIValue(name: field.name, data: data[field.name], type: field.type, version: version) {
                        values.append(value)
                    }
                case .v4, .latest:
                    if let value = try encodeField(
                        name: field.name,
                        rawType: field.type,
                        value: data[field.name] ?? EIP712_JSON.null) {
                        values.append(value)
                    } else {
                        throw EIP712_ABIError.invalidArgumentType
                    }
                }
            }
        }
        try encoder.encode(tuple: values)
        return encoder.data
    }

    // encode field for typedDataSignV4 (support array)
    private func encodeField(
        name: String,
        rawType: String,
        value: EIP712_JSON
    ) throws -> EIP712_ABIValue? {
        if isCustomType(rawType: rawType) {
            let typeValue: Data
            if value == .null {
                typeValue = Data("0x0000000000000000000000000000000000000000000000000000000000000000".utf8)
            } else {
                typeValue = try encodeData(data: value, type: rawType, version: .v4).sha3(.keccak256)
            }
            return try EIP712_ABIValue(typeValue, type: .bytes(32))
        }

        // Arrays
        let components = rawType.components(separatedBy: CharacterSet(charactersIn: "[]"))
        if case let .array(jsons) = value {
            if components.count == 3 && components[1].isEmpty {
                let rawType = components[0]
                let encoder = EIP712_ABIEncoder()
                let values = jsons.compactMap {
                    try? encodeField(name: name, rawType: rawType, value: $0)
                }
                try? encoder.encode(tuple: values)
                return try? EIP712_ABIValue(encoder.data.sha3(.keccak256), type: .bytes(32))
            } else if components.count == 3 && !components[1].isEmpty {
                let num = String(components[1].filter { "0"..."9" ~= $0 })
                guard Int(num) != nil else { return nil }
                let rawType = components[0]
                let encoder = EIP712_ABIEncoder()
                let values = jsons.compactMap {
                    try? encodeField(name: name, rawType: rawType, value: $0)
                }
                try? encoder.encode(tuple: values)
                return try? EIP712_ABIValue(encoder.data.sha3(.keccak256), type: .bytes(32))
            } else {
                throw EIP712_ABIError.invalidArgumentType
            }
        }

        return try makeABIValue(
            name: name,
            data: value,
            type: rawType,
            version: .v4)
    }

    /// Helper func for `encodeData`
    private func makeABIValue(
        name: String,
        data: EIP712_JSON?,
        type: String,
        version: EIP712TypedDataSignVersion
    ) throws -> EIP712_ABIValue? {
        if (type == "string" || type == "bytes"),
           let value = data?.stringValue,
           let valueData = value.data(using: .utf8) {
            return try? EIP712_ABIValue(valueData.sha3(.keccak256), type: .bytes(32))
        } else if type == "bool",
                  let value = data?.boolValue {
            return try? EIP712_ABIValue(value, type: .bool)
        } else if type == "address",
                  let value = data?.stringValue {
            return try? EIP712_ABIValue(value, type: .address)
        } else if type.starts(with: "uint") {
            let size = parseIntSize(type: type, prefix: "uint")
            if size > 0, let value = data?.uintValue {
                return try? EIP712_ABIValue(value, type: .uint(bits: size))
            }
        } else if type.starts(with: "int") {
            let size = parseIntSize(type: type, prefix: "int")
            if size > 0, let value = data?.uintValue {
                return try? EIP712_ABIValue(Int(value), type: .int(bits: size))
            }
        } else if type.starts(with: "bytes") {
            if let length = Int(type.dropFirst("bytes".count)),
                let value = data?.stringValue {
                if value.starts(with: "0x") {
                    let hex = Data(hex: value) 
                    return try? EIP712_ABIValue(hex, type: .bytes(length))
                } else {
                    return try? EIP712_ABIValue(Data(Array(value.utf8)), type: .bytes(length))
                }
            }
        }

        // Arrays
        let components = type.components(separatedBy: CharacterSet(charactersIn: "[]"))
        if components.count == 3 {
            switch version {
            case .v3:
                throw EIP712_ABIError.arrayNotSupported
            case .v4, .latest:
                let components = type.components(separatedBy: CharacterSet(charactersIn: "[]"))
                if case let .array(jsons) = data {
                    if components[1].isEmpty {
                        let rawType = components[0]
                        let encoder = EIP712_ABIEncoder()
                        let values = jsons.compactMap {
                            try? encodeField(name: name, rawType: rawType, value: $0)
                        }
                        try? encoder.encode(tuple: values)
                        return try? EIP712_ABIValue(encoder.data.sha3(.keccak256), type: .bytes(32))
                    } else if !components[1].isEmpty {
                        let num = String(components[1].filter { "0"..."9" ~= $0 })
                        guard Int(num) != nil else { return nil }
                        let rawType = components[0]
                        let encoder = EIP712_ABIEncoder()
                        let values = jsons.compactMap {
                            try? encodeField(name: name, rawType: rawType, value: $0)
                        }
                        try? encoder.encode(tuple: values)
                        return try? EIP712_ABIValue(encoder.data.sha3(.keccak256), type: .bytes(32))
                    } else {
                        throw EIP712_ABIError.invalidArgumentType
                    }
                }
            }
        }

        return nil
    }

    func isCustomType(rawType: String) -> Bool {
        types[rawType] != nil
    }

    /// Helper func for encoding uint / int types
    private func parseIntSize(type: String, prefix: String) -> Int {
        guard type.starts(with: prefix),
            let size = Int(type.dropFirst(prefix.count)) else {
            return -1
        }

        if size < 8 || size > 256 || size % 8 != 0 {
            return -1
        }
        return size
    }
}
