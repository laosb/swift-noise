//
//  OnewayHandshakePattern.swift
//  
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Crypto

public struct OnewayHandshakePattern {
  public static let N = HandshakePatternImpl(
    name: "N",
    messages: [
      .outbound([ .e, .es ])
    ],
    responderPreMessages: [ .s ]
  )
  
  public static let K = HandshakePatternImpl(
    name: "K",
    messages: [
      .outbound([ .e, .es, .ss ])
    ],
    initiatorPreMessages: [ .s ],
    responderPreMessages: [ .s ]
  )
  
  public static let X = HandshakePatternImpl(
    name: "X",
    messages: [
      .outbound([ .e, .es, .s, .ss ])
    ],
    responderPreMessages: [ .s ]
  )
  
  public static let all: [any HandshakePattern] = [N, K, X]
  public static let shared = Self()
}

public extension HandshakePattern {
  static var oneway: OnewayHandshakePattern { .shared }
}
