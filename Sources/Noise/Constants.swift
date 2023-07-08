//
//  Constants.swift
//
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation

/// Noise Protocol constants.
public struct Constants {
  /// Max message length allowed by spec.
  static let maxMessageLength = 65_535
  /// Max transport message count from a single handshake, as defined by spec.
  static let maxMessageCount = UInt64.max
}
