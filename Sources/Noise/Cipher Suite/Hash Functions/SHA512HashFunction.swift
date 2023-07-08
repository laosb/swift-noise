//
//  SHA512HashFunction.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public struct SHA512HashFunction: HashFunction {
  public static let shared = Self()
  
  public let protocolName: String = "SHA512"
  public let hashLength: Int = 64
  
  public func hash(_ data: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: data)) }
  
  public func HKDF(chainingKey: SymmetricKey, inputKeyMaterial: [UInt8], numOutputs: Int) throws -> ([UInt8], [UInt8], [UInt8]?) {
    guard chainingKey.bitCount == 512 else {
      throw HashFunctionError.invalidChainingKeyLength(gotBitCount: chainingKey.bitCount, expectedBitCount: 512)
    }
    return try hkdf(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, numOutputs: numOutputs, usingHashFunction: SHA512.self)
  }
}

extension HashFunction where Self == SHA512HashFunction {
  public static var sha512: SHA512HashFunction { .shared }
}
