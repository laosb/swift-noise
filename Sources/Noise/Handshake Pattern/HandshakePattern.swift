//
//  HandshakePattern.swift
//
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Foundation

public protocol HandshakePattern {
  /// Type of pre-shared initiator static public key.
  associatedtype PSISK
  /// Type of pre-shared responder static public key.
  associatedtype PSRSK
  
  // Is there any practical use of pre-shared ephemeral keys?
  
  var name: String { get set }
  var pskModifierString: String { get set }
  var messages: [HandshakeMessagePattern] { get set }
  var initiatorPreMessages: [HandshakeToken] { get set }
  var responderPreMessages: [HandshakeToken] { get set }
}

public extension HandshakePattern {
  var hasPSK: Bool {
    messages.flatMap { $0.tokens }.contains(.psk)
  }
  
  func psk(_ placement: Int) throws -> some HandshakePattern {
    var pattern = self
    
    if placement == 0 {
      switch pattern.messages[0] {
      case .inbound(let messages):
        pattern.messages[0] = .inbound([.psk] + messages)
      case .outbound(let messages):
        pattern.messages[0] = .outbound([.psk] + messages)
      }
    } else {
      guard pattern.messages.count > (placement - 1) else {
        throw Noise.Errors.custom("Invalid presharedKey placement")
      }
      
      switch pattern.messages[placement - 1] {
      case .inbound(let messages):
        pattern.messages[placement - 1] = .inbound(messages + [.psk])
      case .outbound(let messages):
        pattern.messages[placement - 1] = .outbound(messages + [.psk])
      }
    }
    
    pattern.pskModifierString = "psk\(placement)"
    
    return pattern
  }
}
