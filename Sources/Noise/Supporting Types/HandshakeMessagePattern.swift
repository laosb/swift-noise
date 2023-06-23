//
//  HandshakeMessagePattern.swift
//  
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation

public enum HandshakeMessagePattern {
  case inbound([HandshakeToken])
  case outbound([HandshakeToken])
  
  public var tokens: [HandshakeToken] {
    switch self {
    case .inbound(let tokens):
      return tokens
    case .outbound(let tokens):
      return tokens
    }
  }
}
