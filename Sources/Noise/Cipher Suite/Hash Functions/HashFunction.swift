//
//  HashFunction.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public protocol HashFunction {
  var protocolName: String { get }
  var hashLength: Int { get }
  func hash(_ data: [UInt8]) throws -> [UInt8]
  func HKDF(chainingKey: SymmetricKey, inputKeyMaterial: [UInt8], numOutputs: Int) throws -> ([UInt8], [UInt8], [UInt8]?)
}

public extension HashFunction {
  /// An OSX 10.X compatible implementation of the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
  /// - Note: ChainingKey is expected to be 32 Bytes in length
  /// - Note: [Reference](https://tools.ietf.org/html/rfc5869)
  /// - Note: We instantiate a new HMAC instance for each expansion, instead of calling update() multiple times. We do this because the results are not equal and the reference doc seems to specify the current behavior
  func hkdf<H: Crypto.HashFunction>(
    chainingKey: SymmetricKey,
    inputKeyMaterial: [UInt8],
    numOutputs: Int,
    usingHashFunction: H.Type
  ) throws -> ([UInt8], [UInt8], [UInt8]?) {
    guard numOutputs == 2 || numOutputs == 3 else { throw Noise.Errors.custom("Invalid numOutputs specified. numOutputs must either be 2 or 3") }
    
    var hmac = HMAC<H>(key: chainingKey)
    hmac.update(data: inputKeyMaterial)
    let tempKey = SymmetricKey(data: hmac.finalize())
    
    var hmac1 = HMAC<H>(key: tempKey)
    hmac1.update(data: [0x01])
    let output1 = Array<UInt8>(hmac1.finalize())
    
    var hmac2 = HMAC<H>(key: tempKey)
    hmac2.update(data: output1 + [0x02])
    let output2 = Array<UInt8>(hmac2.finalize())
    
    if numOutputs == 2 {
      return (output1, output2, nil)
    }
    
    var hmac3 = HMAC<H>(key: tempKey)
    hmac3.update(data: output2 + [0x03])
    let output3 = Array<UInt8>(hmac3.finalize())
    
    return (output1, output2, output3)
  }
}

public struct HashFunctionRegistry {
  public private(set) static var functions: [any HashFunction] = [
    .sha256,
    .sha512
  ]
  
  public static var functionNames: [String] {
    functions.map { $0.protocolName }
  }
  
  public static func register(_ function: any HashFunction) {
    if functionNames.contains(function.protocolName) {
      fatalError("Hash Function \(function.protocolName) is already registered.")
    }
    
    functions.append(function)
  }
  
  public static subscript(_ protocolName: String) -> (any HashFunction)? {
    functions.first { $0.protocolName == protocolName }
  }
}
