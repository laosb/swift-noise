//
//  StateDecodingError.swift
//  
//
//  Created by Shibo Lyu on 2023/7/8.
//

import Foundation

enum StateDecodingError: Error {
  case invalidCipherAlgorithm
  case invalidHashFunction
}
