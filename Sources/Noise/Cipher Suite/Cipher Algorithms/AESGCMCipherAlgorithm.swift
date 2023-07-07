//
//  File.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public struct AESGCMCipherAlgorithm: CipherAlgorithm {
  public static let shared = Self()
  
  public let protocolName: String = "AESGCM"
  
  public func encrypt(plaintext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8] {
    let enc = try AES.GCM.seal(plaintext, using: symKey, nonce: getAESGCMNonce(nonce), authenticating: ad)
    
    return Array(enc.ciphertext + enc.tag)
  }
  
  public func decrypt(ciphertext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8] {
    guard ciphertext.count >= 16 else { throw Noise.Errors.custom("Invalid ciphertext length (no tag data found)") }
    
    let sealedBox = try AES.GCM.SealedBox(nonce: getAESGCMNonce(nonce), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
    
    let plaintext = try AES.GCM.open(sealedBox, using: symKey, authenticating: ad)
    
    return Array<UInt8>(plaintext)
  }
  
  private func getAESGCMNonce(_ nonce: UInt64) throws -> AES.GCM.Nonce {
    let padding:[UInt8] = [0x00, 0x00, 0x00, 0x00]
    let bigBytes = nonce.bigEndianBytes // n.bigEndian.toBytes
    
    return try AES.GCM.Nonce(data: padding + bigBytes)
  }
}

extension CipherAlgorithm where Self == AESGCMCipherAlgorithm  {
  public static var AESGCM: AESGCMCipherAlgorithm { .shared }
}

