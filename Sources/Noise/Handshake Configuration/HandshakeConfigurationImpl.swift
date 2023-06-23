//
//  HandshakeConfigurationImpl.swift
//  
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Crypto

public struct HandshakeConfigurationImpl<Pattern: HandshakePattern> {
  let isInitiator: Bool
  let remoteStatic: Curve25519.KeyAgreement.PublicKey?
  let handshakePattern: Pattern
  
  public static func initiator(of pattern: Pattern) -> Self where Pattern.PSRSK == Never {
    .init(isInitiator: true, remoteStatic: nil, handshakePattern: pattern)
  }
  
  public static func responder(of pattern: Pattern) -> Self where Pattern.PSISK == Never {
    .init(isInitiator: false, remoteStatic: nil, handshakePattern: pattern)
  }
  
  public static func initiator(
    of pattern: Pattern,
    remoteStaticKey: Curve25519.KeyAgreement.PublicKey
  ) -> Self where Pattern.PSRSK == Curve25519.KeyAgreement.PublicKey {
    .init(isInitiator: true, remoteStatic: remoteStaticKey, handshakePattern: pattern)
  }
  
  public static func responder(
    of pattern: Pattern,
    remoteStaticKey: Curve25519.KeyAgreement.PublicKey
  ) -> Self where Pattern.PSISK == Curve25519.KeyAgreement.PublicKey {
    .init(isInitiator: false, remoteStatic: remoteStaticKey, handshakePattern: pattern)
  }
}
