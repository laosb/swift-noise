//
//  ChaChaPoly1305CipherAlgorithm.swift
//
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation
import Crypto

public struct ChaChaPoly1305CipherAlgorithm: CipherAlgorithm {
  public static let shared = Self()
  
  public let protocolName: String = "ChaChaPoly"
  
  public func encrypt(plaintext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8] {
    // Encrypt the plaintext using our sym key, nonce, and authenticating data
    let enc = try ChaChaPoly.seal(plaintext, using: symKey, nonce: getChaChaPolyNonce(nonce), authenticating: ad)
    
    return Array(enc.ciphertext + enc.tag)
  }
  
  public func decrypt(ciphertext: [UInt8], usingKey symKey: SymmetricKey, nonce: UInt64, withAuthenticatingData ad: [UInt8]) throws -> [UInt8] {
    guard ciphertext.count >= 16 else { throw CipherAlgorithmError.invalidCiphertextLength }
    
    // Init a ChaChaPoly sealed box using our nonce, the cipher text and the cipher tag (last 16 bytes)
    let sealedBox = try ChaChaPoly.SealedBox(nonce: getChaChaPolyNonce(nonce), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
    
    // Decrypt the sealed box using our sym key, and authenticating data
    let plaintext = try ChaChaPoly.open(sealedBox, using: symKey, authenticating: ad)
    
    return Array(plaintext)
  }
  
  private func getChaChaPolyNonce(_ nonce: UInt64) throws -> ChaChaPoly.Nonce {
    let padding:[UInt8] = [0x00, 0x00, 0x00, 0x00]
    let littleBytes = nonce.littleEndianBytes // n.littleEndian.toBytes
    
    return try ChaChaPoly.Nonce(data: padding + littleBytes)
  }
}

extension CipherAlgorithm where Self == ChaChaPoly1305CipherAlgorithm {
  public static var ChaChaPoly1305: ChaChaPoly1305CipherAlgorithm { .shared }
}

