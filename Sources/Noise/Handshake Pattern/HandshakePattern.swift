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
  
  var name: String { get }
  var messages: [HandshakeMessagePattern] { get }
  var initiatorPreMessages: [HandshakeToken] { get }
  var responderPreMessages: [HandshakeToken] { get }
}
