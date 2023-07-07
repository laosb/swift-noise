//
//  SymmetricState.swift
//  
//
//  Created by Shibo Lyu on 2023/7/7.
//

import Foundation
import Crypto

/// A SymmetricState object contains a CipherState plus `ck` and `h` variables.
/// - Note: It is so-named because it encapsulates all the "symmetric crypto" used by Noise.
/// - Note: During the handshake phase each party has a single SymmetricState, which can be deleted once the handshake is finished.
internal class SymmetricState {
  private let hashFunction:NoiseHashFunction
  private let cipher:NoiseCipherAlgorithm
  
  let HASHLEN:Int
  let cipherState:CipherState
  
  /// A chaining key of `HASHLEN` bytes.
  var ck:SymmetricKey
  
  /// A hash output of `HASHLEN` bytes
  var h:[UInt8]
  
  private var previousCK:SymmetricKey
  private var previousH:[UInt8]
  
  /// Takes an arbitrary-length protocol_name byte sequence (see Section 8).
  ///
  /// Executes the following steps:
  /// ```
  /// 1) if protocol_name is less than or equal to HASHLEN bytes in length
  ///      sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
  ///    else
  ///      Otherwise sets h = HASH(protocol_name).
  ///
  /// 2) Sets ck = h
  ///
  /// 3) Calls InitializeKey(empty)
  /// ```
  init(protocolName:String, cipherSuite:CipherSuite) throws {
    //var buf:ByteBuffer
    //buf.writeString(protocolName)
    guard var proto = protocolName.data(using: .utf8) else { throw Noise.Errors.invalidProtocolName }
    
    hashFunction = cipherSuite.hashFunction
    cipher = cipherSuite.cipher
    
    HASHLEN = hashFunction.hashLength
    
    if proto.count <= HASHLEN {
      while proto.count < HASHLEN { proto.append(0) }
      h = Array<UInt8>(proto)
    } else {
      h = hashFunction.hash(data: Array<UInt8>(proto))
    }
    
    //if h.count > 32 { print("Using first 32 bytes of H") }
    //ck = SymmetricKey(data: h.prefix(32))
    ck = SymmetricKey(data: h)
    
    //Used for checkpoints and rollbacks
    previousCK = ck
    previousH = h
    
    cipherState = try CipherState(cipher: cipher, key: nil)
  }
  
  func mixKey(inputKeyMaterial:[UInt8]) throws {
    let (newCK, tempK, _) = try hashFunction.HKDF(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
    
    //if newCK.count > 32 { print("Warning! Using first 32 bytes of newCK") }
    //ck = SymmetricKey(data: newCK.prefix(32))
    ck = SymmetricKey(data: newCK)
    
    if HASHLEN == 64 {
      // If HASHLEN is 64, then truncates temp_k to 32 bytes.
      try cipherState.initializeKey(key: Array(tempK.prefix(32)))
    } else {
      try cipherState.initializeKey(key: tempK)
    }
  }
  
  /// Sets h = HASH(h || data)
  func mixHash(data:[UInt8]) {
    h = hashFunction.hash(data: h + data)
  }
  
  /// This function is used for handling pre-shared symmetric keys, as described in [section 9](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys)
  func mixKeyAndHash(inputKeyMaterial:[UInt8]) throws {
    // Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    let (newCK, tempH, tempK) = try hashFunction.HKDF(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
    
    //if newCK.count > 32 { print("Warning! Using first 32 bytes of newCK") }
    //ck = SymmetricKey(data: newCK.prefix(32))
    ck = SymmetricKey(data: newCK)
    
    // Calls MixHash(temp_h)
    mixHash(data: tempH)
    
    guard let tk = tempK else { throw Noise.Errors.custom("Failed to generate 3 outputs, tempK is nil") }
    if HASHLEN == 64 {
      // If HASHLEN is 64, then truncates temp_k to 32 bytes.
      try cipherState.initializeKey(key: Array(tk.prefix(32)))
    } else {
      try cipherState.initializeKey(key: tk)
    }
  }
  
  /// Returns h.
  /// - Note: This function should only be called at the end of a handshake, i.e. after the Split() function has been called.
  /// - Note: This function is used for channel binding, as described in Section [11.2](https://noiseprotocol.org/noise.html#channel-binding)
  func getHandshakeHash() -> [UInt8] {
    return h
  }
  
  /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
  /// - Note: If k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
  func encryptAndHash(plaintext:[UInt8]) throws -> [UInt8] {
    let cipherText = try cipherState.encryptWithAD(ad: h, plaintext: plaintext)
    mixHash(data: cipherText)
    return cipherText
  }
  
  /// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
  /// - Note: If k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
  func decryptAndHash(ciphertext:[UInt8]) throws -> [UInt8] {
    let plaintext = try cipherState.decryptWithAD(ad: h, ciphertext: ciphertext)
    mixHash(data: ciphertext)
    return plaintext
  }
  
  /// Returns a pair of CipherState objects for encrypting transport messages
  func split() throws -> (c1:CipherState, c2:CipherState) {
    var (tempK1, tempK2, _) = try hashFunction.HKDF(chainingKey: ck, inputKeyMaterial: [], numOutputs: 2)
    
    if HASHLEN == 64 {
      tempK1 = Array(tempK1.prefix(32))
      tempK2 = Array(tempK2.prefix(32))
    }
    
    let c1 = try CipherState(cipher: cipher, key: SymmetricKey(data: tempK1))
    let c2 = try CipherState(cipher: cipher, key: SymmetricKey(data: tempK2))
    
    return (c1, c2)
  }
  
  func checkpoint() {
    previousCK = ck
    previousH = h
  }
  
  func rollback() {
    ck = previousCK
    h = previousH
  }
  }
