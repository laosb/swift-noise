//
//  CipherState.swift
//
//
//  Created by Shibo Lyu on 2023/7/7.
//

import Foundation
import Crypto

/// A CipherState object contains `k` and `n` variables, which it uses to encrypt and decrypt ciphertexts.
/// - Note: During the handshake phase each party has a single CipherState, but during the transport phase each party has two CipherState objects: one for sending, and one for receiving.
public class CipherState: Codable {
  public let cipher: any CipherAlgorithm
  /// A cipher key of 32 bytes (which may be empty). Empty is a special value which indicates k has not yet been initialized.
  public private(set) var k: SymmetricKey?
  /// An 8-byte (64-bit) unsigned integer nonce.
  public private(set) var n: UInt64
  
  /// A CipherState
  /// - Note: The ++ post-increment operator applied to n means "use the current n value, then increment it".
  /// - Note: The maximum n value (264-1) is reserved for other use. If incrementing n results in 264-1, then any further EncryptWithAd() or DecryptWithAd() calls will signal an error to the caller.
  public init(cipher: CipherAlgorithm, key: SymmetricKey? = nil) throws {
    self.cipher = cipher
    k = key
    n = 0
  }
  
  public func initializeKey(key: [UInt8]) throws {
    if key.count > 32 { print("Warning! Using first 32 bytes of key") }
    k = SymmetricKey(data: key.prefix(32))
    n = 0
  }
  
  /// Returns true if k is non-empty, false otherwise.
  public func hasKey() -> Bool {
    k != nil
  }
  
  /// Sets n = nonce. This function is used for handling out-of-order transport messages, as described in Section 11.4.
  public func setNonce(_ nonce:UInt64) throws {
    n = nonce
  }
  
  /// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
  func encryptWithAD(ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
    guard let symmetricKey = k else {
      // Return the unencrypted plain text
      return plaintext
    }
    
    // Ask our cipher function to encrypt the plaintext using our sym key, nonce, and authenticating data
    let enc = try cipher.encrypt(plaintext: plaintext, usingKey: symmetricKey, nonce: n, withAuthenticatingData: ad)
    
    // Increment the nonce
    n = n + 1
    
    //return Array<UInt8>(enc.ciphertext + enc.tag)
    return enc
  }
  
  /// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext.
  /// - Note: If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
  func decryptWithAD(ad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
    guard let symmetricKey = k else {
      // Return ciphertext as is
      return ciphertext
    }
    
    // Ask our cipher function to decrypt the ciphertext using our sym key, nonce, and authenticating data
    let plaintext = try cipher.decrypt(ciphertext: ciphertext, usingKey: symmetricKey, nonce: n, withAuthenticatingData: ad)
    
    // Increment the nonce
    n = n + 1
    
    // Return the plaintext
    return plaintext
  }
  
  /// Swaps out the current Key for the new specified one
  public func rekey(key: SymmetricKey) {
    k = key
  }
  
  public func encrypt(plaintext: [UInt8]) throws -> [UInt8] {
    return try self.encryptWithAD(ad: [], plaintext: plaintext)
  }
  
  public func decrypt(ciphertext: [UInt8]) throws -> [UInt8] {
    return try self.decryptWithAD(ad: [], ciphertext: ciphertext)
  }
  
  // MARK: Codable conformance
  enum CodingKeys: CodingKey {
    case cipher, k, n
  }
  
  enum DecodeError: Error {
    case invalidCipherAlgorithm
  }
  
  public required convenience init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    let cipherAlgorithmName = try container.decode(String.self, forKey: .cipher)
    guard let cipher = CipherAlgorithmRegistry[cipherAlgorithmName] else {
      throw DecodeError.invalidCipherAlgorithm
    }
    
    let k = try container.decodeIfPresent(SymmetricKey.self, forKey: .k)
    let n = try container.decode(UInt64.self, forKey: .n)
    
    try self.init(cipher: cipher, key: k)
    
    self.n = n
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    try container.encode(cipher.protocolName, forKey: .cipher)
    try container.encode(k, forKey: .k)
    try container.encode(n, forKey: .n)
  }
}
