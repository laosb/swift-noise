//
//  HandshakeConfiguration.swift
//
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation
import Crypto

public protocol HandshakeConfiguration {
  associatedtype Pattern: HandshakePattern
  
  var isInitiator: Bool { get }
  var staticKey: Curve25519.KeyAgreement.PrivateKey { get }
  var remoteStaticKey: Curve25519.KeyAgreement.PublicKey? { get }
  var ephemeralKey: Curve25519.KeyAgreement.PrivateKey? { get }
  var remoteEphemeralKey: Curve25519.KeyAgreement.PublicKey? { get }
  var presharedKey: [UInt8]? { get }
  var handshakePattern: Pattern { get }
  var cipherSuite: CipherSuite { get }
}
