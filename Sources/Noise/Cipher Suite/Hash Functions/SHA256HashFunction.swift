//
//  SHA256HashFunction.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public struct SHA256HashFunction: HashFunction {
  public static let shared = Self()
  
  public let protocolName: String = "SHA256"
  public let hashLength: Int = 32
  
  public func hash(_ data: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: data)) }
  
  public func HKDF(chainingKey: SymmetricKey, inputKeyMaterial: [UInt8], numOutputs: Int) throws -> ([UInt8], [UInt8], [UInt8]?) {
    guard chainingKey.bitCount == 256 else {
      throw HashFunctionError.invalidChainingKeyLength(gotBitCount: chainingKey.bitCount, expectedBitCount: 256)
    }
    return try hkdf(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, numOutputs: numOutputs, usingHashFunction: SHA256.self)
  }
}

extension HashFunction where Self == SHA256HashFunction {
  public static var sha256: SHA256HashFunction { .shared }
}
