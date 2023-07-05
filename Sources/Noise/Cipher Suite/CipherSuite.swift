//
//  CipherSuite.swift
//  
//
//  Created by Shibo Lyu on 2023/6/24.
//

import Foundation

public struct CipherSuite {
  let keyCurve: KeyCurve
  let cipher: CipherAlgorithm
  let hashFunction: HashFunction
  
  public init(_ keyCurve: KeyCurve, _ cipher: CipherAlgorithm, _ hashFunction: HashFunction) {
    self.keyCurve = keyCurve
    self.cipher = cipher
    self.hashFunction = hashFunction
  }
  
  internal var protocolName:String {
    return "\(keyCurve.protocolName)_\(cipher.protocolName)_\(hashFunction.protocolName)"
  }
}
