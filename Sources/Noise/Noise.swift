//
//  Noise.swift
//
//
//  Created by Brandon Toms on 5/1/22.
//
//  A Noise Protocol handshake implementation

import Crypto

public struct Noise {
    
    /// Max message length allowed by spec
    static let maxMessageLength = 65_535
    
    public enum Errors:Error {
        case invalidPSK
        case remoteEphemeralKeyAlreadySet
        case remoteStaticKeyAlreadySet
        case unexpectedPayloadLength
        case invalidProtocolName
        case invalidChainingKey
        case invalidHKDFOutput
        case unsupportedPreMessage
        case custom(String)
    }
    
    

}
