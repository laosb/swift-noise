//
//  HandshakeConfigurationImpl.swift
//
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Crypto

public struct HandshakeConfigurationImpl<Pattern: HandshakePattern>: HandshakeConfiguration {
  public let isInitiator: Bool
  public let staticKey: PrivateKey
  public let remoteStaticKey: PublicKey?
  public var ephemeralKey: PrivateKey?
  public var remoteEphemeralKey: PublicKey?
  public let presharedKey: [UInt8]?
  public let prologue: [UInt8]?
  public let handshakePattern: Pattern
  public var cipherSuite: CipherSuite
  
  public init(
    isInitiator: Bool,
    staticKey: PrivateKey,
    remoteStaticKey: PublicKey?,
    ephemeralKey: PrivateKey? = nil,
    remoteEphemeralKey: PublicKey? = nil,
    presharedKey: [UInt8]?,
    prologue: [UInt8]?,
    handshakePattern: Pattern,
    cipherSuite: CipherSuite
  ) {
    if handshakePattern.hasPSK && presharedKey == nil {
      fatalError("Handshake pattern requires a preshared key but none is provided.")
    }
    
    self.isInitiator = isInitiator
    self.staticKey = staticKey
    self.remoteStaticKey = remoteStaticKey
    self.ephemeralKey = ephemeralKey
    self.remoteEphemeralKey = remoteEphemeralKey
    self.presharedKey = presharedKey
    self.prologue = prologue
    self.handshakePattern = handshakePattern
    self.cipherSuite = cipherSuite
  }
}
