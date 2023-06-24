//
//  CipherAlgorithm.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public protocol CipherAlgorithm {
  var protocolName: String { get }
  func encrypt(plainText: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8]
  func decrypt(ciphertext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8]
}
