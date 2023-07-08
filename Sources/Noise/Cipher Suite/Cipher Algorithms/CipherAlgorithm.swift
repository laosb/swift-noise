//
//  CipherAlgorithm.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

/// A protocol for cipher algorithm to use in Noise Protocol.
///
/// It's designed to be extensible, so you can add your own cipher algorithm.
///
/// To make you cipher algorithm correctly decodable & encodable, register it in `CipherAlgorithmRegistry`.
public protocol CipherAlgorithm {
  var protocolName: String { get }
  func encrypt(plaintext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8]
  func decrypt(ciphertext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8]
}

public struct CipherAlgorithmRegistry {  
  public private(set) static var algorithms: [any CipherAlgorithm] = [
    .AESGCM,
    .ChaChaPoly1305
  ]
  
  public static var algorithmNames: [String] {
    algorithms.map { $0.protocolName }
  }
  
  public static func register(_ algorithm: any CipherAlgorithm) {
    if algorithmNames.contains(algorithm.protocolName) {
      fatalError("Algorithm name \(algorithm.protocolName) already exists.")
    }
    
    algorithms.append(algorithm)
  }
  
  public static subscript(_ protocolName: String) -> (any CipherAlgorithm)? {
    algorithms.first { $0.protocolName == protocolName }
  }
}
