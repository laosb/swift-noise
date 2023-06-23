//
//  FundamentalHandshakePattern.swift
//  
//
//  Created by Shibo Lyu on 2023/6/23.
//

import Crypto

public struct FundamentalHandshakePattern {
  /// XX handshake pattern.
  /// ```
  ///   -> e
  ///   <- e, ee, s, es
  ///   -> s, se
  /// ```
  public static let XX = HandshakePatternImpl(
    name: "XX",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee, .s, .es ]),
      .outbound([ .s, .se ])
    ]
  )
  
  /// NN handshake pattern.
  /// ```
  /// -> e
  /// <- e, ee
  /// ```
  public static let NN = HandshakePatternImpl(
    name: "NN",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee ])
    ]
  )
  
  public static let NX = HandshakePatternImpl(
    name: "NX",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee, .s, .es ])
    ]
  )
  
  public static let XN = HandshakePatternImpl(
    name: "XN",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee ]),
      .outbound([ .s, .se ])
    ]
  )
  
  public static let IN = HandshakePatternImpl(
    name: "IN",
    messages: [
      .outbound([ .e, .s ]),
      .inbound( [ .e, .ee, .se ])
    ]
  )
  
  public static let IX = HandshakePatternImpl(
    name: "IX",
    messages: [
      .outbound([ .e, .s ]),
      .inbound( [ .e, .ee, .se, .s, .es ])
    ]
  )

  public static let KN = HandshakePatternImpl(
    name: "KN",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee, .se ])
    ],
    initiatorPreMessages: [ .s ]
  )
  
  public static let KX = HandshakePatternImpl(
    name: "KX",
    messages: [
      .outbound([ .e ]),
      .inbound( [ .e, .ee, .se, .s, .es ])
    ],
    initiatorPreMessages: [ .s ]
  )
  
  public static let NK = HandshakePatternImpl(
    name: "NK",
    messages: [
      .outbound([ .e, .es ]),
      .inbound( [ .e, .ee ])
    ],
    responderPreMessages: [ .s ]
  )
  
  public static let XK = HandshakePatternImpl(
    name: "XK",
    messages: [
      .outbound([ .e, .es ]),
      .inbound( [ .e, .ee ]),
      .outbound([ .s, .se ])
    ],
    responderPreMessages: [ .s ]
  )
  
  public static let IK = HandshakePatternImpl(
    name: "IK",
    messages: [
      .outbound([ .e, .es, .s, .ss ]),
      .inbound( [ .e, .ee, .se ])
    ],
    responderPreMessages: [ .s ]
  )

  public static let KK = HandshakePatternImpl(
    name: "KK",
    messages: [
      .outbound([ .e, .es, .ss ]),
      .inbound( [ .e, .ee, .se ])
    ],
    initiatorPreMessages: [ .s ],
    responderPreMessages: [ .s ]
  )
  
  public static let all: [any HandshakePattern] = [XX, NN, NX, XN, IN, IX, KN, NK, KK, KX, XK, IK]
  public static let shared = Self()
}

public extension HandshakePattern {
  static var fundamental: FundamentalHandshakePattern { .shared }
}
