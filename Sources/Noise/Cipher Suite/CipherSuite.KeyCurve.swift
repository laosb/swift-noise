//
//  CipherSuite.KeyCurve.swift
//  
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation

extension CipherSuite {
  public enum KeyCurve {
    case ed25519
    
    public var protocolName: String {
      switch self {
      case .ed25519: return "25519"
      }
    }
  }
}
