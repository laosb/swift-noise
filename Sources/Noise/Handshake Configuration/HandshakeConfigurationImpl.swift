//
//  HandshakeConfigurationImpl.swift
//
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Crypto

public struct HandshakeConfigurationImpl<Pattern: HandshakePattern>: HandshakeConfiguration {
  public typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
  public typealias PublicKey = Curve25519.KeyAgreement.PublicKey
  
  public let isInitiator: Bool
  public let staticKey: PrivateKey
  public let remoteStaticKey: PublicKey?
  public var ephemeralKey: PrivateKey?
  public var remoteEphemeralKey: PublicKey?
  public let presharedKey: [UInt8]?
  public let prologue: [UInt8]?
  public let handshakePattern: Pattern
  public var cipherSuite: CipherSuite
  
  public static func initiator(
    of pattern: Pattern,
    _ cipherSuite: CipherSuite,
    staticKey: PrivateKey,
    presharedKey: [UInt8]? = nil,
    prologue: [UInt8]? = nil,
    ephemeralKey: PrivateKey? = nil,
    remoteEphemeralKey: PublicKey? = nil
  ) -> Self where Pattern.PSRSK == Never {
    .init(
      isInitiator: true,
      staticKey: staticKey,
      remoteStaticKey: nil,
      ephemeralKey: ephemeralKey,
      remoteEphemeralKey: remoteEphemeralKey,
      presharedKey: presharedKey,
      prologue: prologue,
      handshakePattern: pattern,
      cipherSuite: cipherSuite
    )
  }
  
  public static func responder(
    of pattern: Pattern,
    _ cipherSuite: CipherSuite,
    staticKey: PrivateKey,
    presharedKey: [UInt8]? = nil,
    prologue: [UInt8]? = nil,
    ephemeralKey: PrivateKey? = nil,
    remoteEphemeralKey: PublicKey? = nil
  ) -> Self where Pattern.PSISK == Never {
    .init(
      isInitiator: false,
      staticKey: staticKey,
      remoteStaticKey: nil,
      ephemeralKey: ephemeralKey,
      remoteEphemeralKey: remoteEphemeralKey,
      presharedKey: presharedKey,
      prologue: prologue,
      handshakePattern: pattern,
      cipherSuite: cipherSuite
    )
  }
  
  public static func initiator(
    of pattern: Pattern,
    _ cipherSuite: CipherSuite,
    staticKey: PrivateKey,
    remoteStaticKey: Curve25519.KeyAgreement.PublicKey,
    presharedKey: [UInt8]? = nil,
    prologue: [UInt8]? = nil,
    ephemeralKey: PrivateKey? = nil,
    remoteEphemeralKey: PublicKey? = nil
  ) -> Self where Pattern.PSRSK == Curve25519.KeyAgreement.PublicKey {
    .init(
      isInitiator: true,
      staticKey: staticKey,
      remoteStaticKey: remoteStaticKey,
      ephemeralKey: ephemeralKey,
      remoteEphemeralKey: remoteEphemeralKey,
      presharedKey: presharedKey,
      prologue: prologue,
      handshakePattern: pattern,
      cipherSuite: cipherSuite
    )
  }
  
  public static func responder(
    of pattern: Pattern,
    _ cipherSuite: CipherSuite,
    staticKey: PrivateKey,
    remoteStaticKey: Curve25519.KeyAgreement.PublicKey,
    presharedKey: [UInt8]? = nil,
    prologue: [UInt8]? = nil,
    ephemeralKey: PrivateKey? = nil,
    remoteEphemeralKey: PublicKey? = nil
  ) -> Self where Pattern.PSISK == Curve25519.KeyAgreement.PublicKey {
    .init(
      isInitiator: false,
      staticKey: staticKey,
      remoteStaticKey: remoteStaticKey,
      ephemeralKey: ephemeralKey,
      remoteEphemeralKey: remoteEphemeralKey,
      presharedKey: presharedKey,
      prologue: prologue,
      handshakePattern: pattern,
      cipherSuite: cipherSuite
    )
  }
}
