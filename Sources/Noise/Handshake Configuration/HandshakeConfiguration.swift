//
//  HandshakeConfiguration.swift
//
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation
import Crypto

public protocol HandshakeConfiguration {
  typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
  typealias PublicKey = Curve25519.KeyAgreement.PublicKey
  
  associatedtype Pattern: HandshakePattern
  
  var isInitiator: Bool { get }
  var staticKey: PrivateKey { get }
  var remoteStaticKey: PublicKey? { get }
  var ephemeralKey: PrivateKey? { get }
  var remoteEphemeralKey: PublicKey? { get }
  var presharedKey: [UInt8]? { get }
  var prologue: [UInt8]? { get }
  var handshakePattern: Pattern { get }
  var cipherSuite: CipherSuite { get }
  
  init(
    isInitiator: Bool,
    staticKey: PrivateKey,
    remoteStaticKey: PublicKey?,
    ephemeralKey: PrivateKey?,
    remoteEphemeralKey: PublicKey?,
    presharedKey: [UInt8]?,
    prologue: [UInt8]?,
    handshakePattern: Pattern,
    cipherSuite: CipherSuite
  )
}

public extension HandshakeConfiguration {
  var fullProtocolName: String {
    "Noise_\(handshakePattern.name)\(handshakePattern.pskModifierString)_\(cipherSuite.protocolName)"
  }
  
  static func initiator(
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
  
  static func responder(
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
  
  static func initiator(
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
  
  static func responder(
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
