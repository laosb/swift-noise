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
}

public extension HandshakeConfiguration {
  var fullProtocolName: String {
    "Noise_\(handshakePattern.name)\(handshakePattern.pskModifierString)_\(cipherSuite.protocolName)"
  }
}
