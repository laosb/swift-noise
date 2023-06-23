//
//  UIntToBytesConvertable.swift
//  
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation

protocol UIntToBytesConvertable {
  var littleEndianBytes: [UInt8] { get }
  var bigEndianBytes: [UInt8] { get }
}

extension UIntToBytesConvertable {
  func toByteArr<T: BinaryInteger>(endian: T, count: Int) -> [UInt8] {
    var _endian = endian
    let bytePtr = withUnsafePointer(to: &_endian) {
      $0.withMemoryRebound(to: UInt8.self, capacity: count) {
        UnsafeBufferPointer(start: $0, count: count)
      }
    }
    return [UInt8](bytePtr)
  }
}
