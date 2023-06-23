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
  var remoteStatic: Curve25519.KeyAgreement.PublicKey? { get }
  var handshakePattern: Pattern { get }
}
