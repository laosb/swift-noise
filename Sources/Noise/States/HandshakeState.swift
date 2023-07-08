//
//  HandshakeState.swift
//
//
//  Created by Shibo Lyu on 2023/7/7.
//

import Foundation
import Crypto

/// A HandshakeState object contains a `SymmetricState` plus DH variables (`s`, `e`, `rs`, `re`) and a variable representing the handshake pattern.
/// - Note: During the handshake phase each party has a single HandshakeState, which can be deleted once the handshake is finished.
public class HandshakeState: Codable {
  enum HandshakeError: Error {
    enum ErrorStage {
      case preMessage(isInitiator: Bool)
      case token(HandshakeToken)
      /// When calling methods to get keys.
      case get
    }
    
    case invalidPresharedKey
    case unsupportedPreMessage
    case noRemoteStaticKey(ErrorStage)
    case noRemoteEphemeralKey(ErrorStage)
    case noLocalEphemeralKey(ErrorStage)
    case remoteStaticKeyAlreadySet
    case remoteEphemeralKeyAlreadySet
    case writeWhenShouldRead
    case readWhenShouldWrite
    case handshakeFinished
    case messageTooLong
    case messageTooShort
    case handshakeInProgress
  }
  
  
  public typealias PublicKey = Curve25519.KeyAgreement.PublicKey
  public typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey
  
  private let symmetricState: SymmetricState
  
  /// The static key of the local party.
  private var s: PrivateKey
  /// The ephemeral key of the local party.
  private var e: PrivateKey?
  /// The static key of the remote party.
  private var rs: PublicKey?
  /// The ephemeral key of the remote party.
  private var re: PublicKey?
  private var psk: [UInt8] = []
  
  let initiator: Bool
  private var messages: [HandshakeMessagePattern]
  private let prologue: [UInt8]
  
  public private(set) var msgIndex: Int = 0
  
  public let protocolName: String
  
  public init(config: any HandshakeConfiguration) throws {
    /// Sets message_patterns to the message patterns from handshake_pattern.
    messages = config.handshakePattern.messages
    prologue = config.prologue ?? []
    
    /// Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    initiator = config.isInitiator
    s = config.staticKey
    e = config.ephemeralKey
    rs = config.remoteStaticKey
    re = config.remoteEphemeralKey
    
    if let psk = config.presharedKey {
      guard psk.count == 32 else {
        throw HandshakeError.invalidPresharedKey
      }
      self.psk = psk
    }
    
    protocolName = config.fullProtocolName
    
    /// Calls InitializeSymmetric(protocol_name)
    symmetricState = try SymmetricState(protocolName: protocolName, cipherSuite: config.cipherSuite)
    
    /// Calls MixHash(prologue)
    try symmetricState.mixHash(data: prologue)
    
    for preMessage in config.handshakePattern.initiatorPreMessages {
      switch preMessage {
      case .s:
        if initiator {
          try symmetricState.mixHash(data: Array<UInt8>(s.publicKey.rawRepresentation) )
        } else {
          guard let rs else {
            throw HandshakeError.noRemoteStaticKey(.preMessage(isInitiator: false))
          }
          try symmetricState.mixHash(data: Array<UInt8>(rs.rawRepresentation) )
        }
        
      case .e:
        if initiator {
          guard let e else {
            throw HandshakeError.noLocalEphemeralKey(.preMessage(isInitiator: true))
          }
          try symmetricState.mixHash(data: Array<UInt8>(e.publicKey.rawRepresentation) )
        } else {
          guard let re else {
            throw HandshakeError.noRemoteEphemeralKey(.preMessage(isInitiator: false))
          }
          try symmetricState.mixHash(data: Array<UInt8>(re.rawRepresentation) )
        }
        
      default:
        throw HandshakeError.unsupportedPreMessage
      }
    }
    
    for preMessage in config.handshakePattern.responderPreMessages {
      switch preMessage {
      case .s:
        if !initiator {
          try symmetricState.mixHash(data: Array<UInt8>(s.publicKey.rawRepresentation) )
        } else {
          guard let rs else {
            throw HandshakeError.noRemoteStaticKey(.preMessage(isInitiator: true))
          }
          try symmetricState.mixHash(data: Array<UInt8>(rs.rawRepresentation) )
        }
        
      case .e:
        if !initiator {
          guard let e else {
            throw HandshakeError.noLocalEphemeralKey(.preMessage(isInitiator: false))
          }
          try symmetricState.mixHash(data: Array<UInt8>(e.publicKey.rawRepresentation) )
        } else {
          guard let re else {
            throw HandshakeError.noRemoteEphemeralKey(.preMessage(isInitiator: true))
          }
          try symmetricState.mixHash(data: Array<UInt8>(re.rawRepresentation) )
        }
        
      default:
        throw HandshakeError.unsupportedPreMessage
      }
    }
  }
  
  /// Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into
  /// - Note: This method aborts if any EncryptAndHash() call returns an error
  public func writeMessage(payload: [UInt8]) throws -> (buffer: [UInt8], c1: CipherState?, c2: CipherState?) {
    
    guard self.shouldWrite() else { throw HandshakeError.writeWhenShouldRead }
    guard msgIndex < messages.count else { throw HandshakeError.handshakeFinished }
    guard payload.count < Noise.maxMessageLength else { throw HandshakeError.messageTooLong }
    
    // Get the next set of messages to process...
    let pattern = messages[msgIndex].tokens
    
    var messageBuffer: [UInt8] = []
    
    // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
    for message in pattern {
      switch message {
      case .e:
        // For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key).
        if e == nil { e = generateKeypair() }
        //else { print("Warning: e already set, this is only acceptable during testing") }
        //messageBuffer.writeBytes(e!.publicKey.rawRepresentation)
        messageBuffer.append(contentsOf: e!.publicKey.rawRepresentation)
        try symmetricState.mixHash(data: Array<UInt8>(e!.publicKey.rawRepresentation))
        if psk.count > 0 {
          try symmetricState.mixKey(inputKeyMaterial: Array<UInt8>(e!.publicKey.rawRepresentation))
        }
        
      case .s:
        // For "s": Appends EncryptAndHash(s.public_key) to the buffer.
        let spk = try symmetricState.encryptAndHash(plaintext: Array<UInt8>(s.publicKey.rawRepresentation) )
        messageBuffer.append(contentsOf: spk)
        //messageBuffer.writeBytes(spk)
        
      case .ee:
        // For "ee": Calls MixKey(DH(e, re)).
        guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.ee)) }
        guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.ee)) }
        try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: re))
        
      case .es:
        // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
        if initiator {
          guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.es)) }
          guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.es)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: rs))
        } else {
          guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.es)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: re))
        }
        
      case .se:
        // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
        if initiator {
          guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.se)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: re))
        } else {
          guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.se)) }
          guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.se)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: rs))
        }
        
      case .ss:
        // For "ss": Calls MixKey(DH(s, rs)).
        guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.ss)) }
        try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: rs))
        
      case .psk:
        guard psk.count == 32 else { throw HandshakeError.invalidPresharedKey }
        try symmetricState.mixKeyAndHash(inputKeyMaterial: psk)
      }
    }
    
    // Increment our message index counter
    msgIndex += 1
    
    // Appends EncryptAndHash(payload) to the buffer.
    try messageBuffer.append(contentsOf: symmetricState.encryptAndHash(plaintext: payload))
    
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    if msgIndex >= messages.count {
      let split = try symmetricState.split()
      return (buffer: messageBuffer, c1: split.c1, c2: split.c2)
    }
    
    return (buffer: messageBuffer, c1: nil, c2: nil)
  }
  
  /// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into
  /// - Note: This method aborts if any DecryptAndHash() call returns an error
  public func readMessage(_ inboundMessage: [UInt8]) throws -> (payload: [UInt8], c1: CipherState?, c2: CipherState?) {
    guard self.shouldRead() else { throw HandshakeError.readWhenShouldWrite }
    guard msgIndex < messages.count else { throw HandshakeError.handshakeFinished }
    
    symmetricState.checkpoint()
    
    // Get the next set of messages to process...
    let pattern = messages[msgIndex].tokens
    
    var inboundMsg: [UInt8] = inboundMessage //Array(inboundMessage.readableBytesView)
    var bytesRead: Int = 0
    
    // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern
    for message in pattern {
      //print("Consuming message \(message)")
      switch message {
      case .e, .s:
        var expected: Int = 32
        if message == .s && symmetricState.cipherState.hasKey() {
          expected += 16
        }
        guard inboundMsg.count >= expected else { throw HandshakeError.messageTooShort }
        
        do {
          if message == .e {
            // For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
            guard re == nil else { throw HandshakeError.remoteEphemeralKeyAlreadySet }
            //guard inboundMsg.count >= symmetricState.HASHLEN else { throw Noise.Errors.custom("Message payload unexpected length") }
            re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: inboundMsg.prefix(expected))
            try symmetricState.mixHash(data: Array<UInt8>(re!.rawRepresentation) )
            bytesRead += expected
            if psk.count > 0 {
              try symmetricState.mixKey(inputKeyMaterial: Array<UInt8>(re!.rawRepresentation) )
            }
            
          } else if message == .s {
            // For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
            guard rs == nil else { throw HandshakeError.remoteStaticKeyAlreadySet }
            rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: symmetricState.decryptAndHash(ciphertext: Array(inboundMsg.prefix(expected))))
            bytesRead += expected
            
          }
        } catch {
          symmetricState.rollback()
          // if rSet { rs = nil }
          throw error
        }
        inboundMsg = Array(inboundMsg.dropFirst(expected))
        
      case .ee:
        // For "ee": Calls MixKey(DH(e, re)).
        guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.ee)) }
        guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.ee)) }
        try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: re))
        
      case .es:
        // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
        if initiator {
          guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.es)) }
          guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.es)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: rs))
        } else {
          guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.es)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: re))
        }
        
      case .se:
        // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
        if initiator {
          guard let re else { throw HandshakeError.noRemoteEphemeralKey(.token(.se)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: re))
        } else {
          guard let e else { throw HandshakeError.noLocalEphemeralKey(.token(.se)) }
          guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.se)) }
          try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: e, pubKey: rs))
        }
        
      case .ss:
        // For "ss": Calls MixKey(DH(s, rs)).
        guard let rs else { throw HandshakeError.noRemoteStaticKey(.token(.ss)) }
        try symmetricState.mixKey(inputKeyMaterial: dh(keyPair: s, pubKey: rs))
        
      case .psk:
        guard psk.count == 32 else { throw HandshakeError.invalidPresharedKey }
        try symmetricState.mixKeyAndHash(inputKeyMaterial: psk)
      }
    }
    
    var decryptedPayload: [UInt8] = []
    //var decryptedPayload = ByteBuffer()
    
    do {
      
      // Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
      //decryptedPayload.writeBytes( try symmetricState.decryptAndHash(ciphertext: inboundMsg ) )
      decryptedPayload.append(contentsOf: try symmetricState.decryptAndHash(ciphertext: inboundMsg) )
    } catch {
      
      // Rollback
      symmetricState.rollback()
      rs = nil
      throw error
      
    }
    
    msgIndex += 1
    
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    if msgIndex >= messages.count {
      let split = try symmetricState.split()
      return (payload: decryptedPayload, c1: split.c1, c2: split.c2)
    }
    
    return (payload: decryptedPayload, c1: nil, c2: nil)
  }
  
  public func shouldRead() -> Bool {
    !shouldWrite()
  }
  
  public func shouldWrite() -> Bool {
    guard messages.count > msgIndex else { return false }
    let msg = messages[msgIndex]
    switch msg {
    case .inbound:
      return self.initiator != true
    case .outbound:
      return self.initiator == true
    }
  }
  
  private func generateKeypair() -> Curve25519.KeyAgreement.PrivateKey {
    return Curve25519.KeyAgreement.PrivateKey()
  }
  
  private func dh(keyPair: PrivateKey, pubKey: PublicKey) throws -> [UInt8] {
    let shared = try keyPair.sharedSecretFromKeyAgreement(with: pubKey)
    return shared.withUnsafeBytes { Array($0) }
  }
  
  public func encrypt(msg: [UInt8]) throws -> [UInt8] {
    return try symmetricState.encryptAndHash(plaintext: msg)
  }
  
  public func decrypt(msg: [UInt8]) throws -> [UInt8] {
    return try symmetricState.decryptAndHash(ciphertext: msg)
  }
  
  /// ChannelBinding provides a value that uniquely identifies the session and can
  /// be used as a channel binding. It is an error to call this method before the
  /// handshake is complete.
  public func channelBinding() throws -> [UInt8] {
    guard msgIndex >= messages.count else { throw HandshakeError.handshakeInProgress }
    return symmetricState.h
  }
  
  /// PeerStatic returns the static key provided by the remote peer during
  /// a handshake. It is an error to call this method if a handshake message
  /// containing a static key has not been read.
  public func peerStatic() throws -> PublicKey {
    guard let rs else { throw HandshakeError.noRemoteStaticKey(.get) }
    return rs
  }
  
  /// PeerEphemeral returns the ephemeral key provided by the remote peer during
  /// a handshake. It is an error to call this method if a handshake message
  /// containing a static key has not been read.
  public func peerEphemeral() throws -> PublicKey {
    guard let re else { throw HandshakeError.noRemoteEphemeralKey(.get) }
    return re
  }
  
  /// LocalEphemeral returns the local ephemeral key pair generated during a handshake.
  public func localEphemeral() throws -> PrivateKey {
    guard let e else { throw HandshakeError.noLocalEphemeralKey(.get) }
    return e
  }
  
  /// MessageIndex returns the current handshake message id
  public func messageIndex() -> Int {
    return msgIndex
  }
}
