//
//  UInt64+UIntToBytesConvertable.swift
//  
//
//  Created by Shibo Lyu on 2023/6/22.
//

import Foundation

extension UInt64: UIntToBytesConvertable {
  var littleEndianBytes: [UInt8] {
    toByteArr(endian: self.littleEndian, count: MemoryLayout<UInt64>.size)
  }
  var bigEndianBytes: [UInt8] {
    toByteArr(endian: self.bigEndian, count: MemoryLayout<UInt64>.size)
  }
}
