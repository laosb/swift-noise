//
//  SymmetricKey+Codable.swift
//
//
//  Created by Shibo Lyu on 2023/7/7.
//

import Foundation
import Crypto

extension SymmetricKey: Codable {
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(self.withUnsafeBytes { Data(Array($0)) })
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let data = try container.decode(Data.self)
    self = SymmetricKey(data: data)
  }
}
