//
//  HandshakePatternImpl.swift
//
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation
import Crypto

public struct HandshakePatternImpl<PSISK, PSRSK>: HandshakePattern {
  public var name: String
  /// Modifier string for pre-shared key.
  ///
  /// The ``psk(_:)`` modifier will handle this string so you should not modify it manually.
  public var pskModifierString: String = ""
  public var messages: [HandshakeMessagePattern]
  public var initiatorPreMessages: [HandshakeToken]
  public var responderPreMessages: [HandshakeToken]
  
  public init(
    name: String,
    messages: [HandshakeMessagePattern]
  ) where PSISK == Never, PSRSK == Never {
    self.name = name
    self.messages = messages
    self.initiatorPreMessages = []
    self.responderPreMessages = []
  }
  
  public init(
    name: String,
    messages: [HandshakeMessagePattern],
    initiatorPreMessages: [HandshakeToken]
  ) where PSISK == Curve25519.KeyAgreement.PublicKey, PSRSK == Never {
    guard initiatorPreMessages.contains(.s) else {
      fatalError("Practically, pre-messages must contain a static key.")
    }
    
    self.name = name
    self.messages = messages
    self.initiatorPreMessages = initiatorPreMessages
    self.responderPreMessages = []
  }
  
  public init(
    name: String,
    messages: [HandshakeMessagePattern],
    responderPreMessages: [HandshakeToken]
  ) where PSISK == Never, PSRSK == Curve25519.KeyAgreement.PublicKey {
    guard responderPreMessages.contains(.s) else {
      fatalError("Practically, pre-messages must contain a static key.")
    }
    
    self.name = name
    self.messages = messages
    self.initiatorPreMessages = []
    self.responderPreMessages = responderPreMessages
  }
  
  public init(
    name: String,
    messages: [HandshakeMessagePattern],
    initiatorPreMessages: [HandshakeToken],
    responderPreMessages: [HandshakeToken]
  ) where PSISK == Curve25519.KeyAgreement.PublicKey, PSRSK == Curve25519.KeyAgreement.PublicKey {
    guard
      initiatorPreMessages.contains(.s),
      responderPreMessages.contains(.s)
    else {
      fatalError("Practically, pre-messages must contain a static key.")
    }
    
    self.name = name
    self.messages = messages
    self.initiatorPreMessages = initiatorPreMessages
    self.responderPreMessages = responderPreMessages
  }
}
