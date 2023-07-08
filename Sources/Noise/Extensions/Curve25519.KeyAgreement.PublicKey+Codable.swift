//
//  Curve25519.KeyAgreement.PublicKey+Codable.swift
//
//
//  Created by Shibo Lyu on 2023/7/8.
//

import Foundation
import Crypto

extension Curve25519.KeyAgreement.PublicKey: Codable {
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(self.rawRepresentation)
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let data = try container.decode(Data.self)
    self = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)
  }
}
