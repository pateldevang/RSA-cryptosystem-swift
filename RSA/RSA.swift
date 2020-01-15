//
//  RSA.swift
//  RSA
//
//  Created by Devang Patel on 01/11/19.
//  Copyright © 2019 Devang Patel. All rights reserved.
//

import Foundation
import Security


class RSAWrapper {
    
    //MARK: - Define public and private keys of type SecKey
    private var publicKey : SecKey?
    private var privateKey : SecKey?
    
    
    //MARK: - Key pair generating function
    func generateKeyPair(keySize: UInt, privateTag: String, publicTag: String) -> Bool {
        
        self.publicKey = nil
        self.privateKey = nil
        
        //Checking Key size after generation
        if (keySize != 512 && keySize != 1024 && keySize != 2048) {
            // Failed
            print("Key size is wrong")
            return false
        }
        
        // Initializing public key Parameters 
        let publicKeyParameters: [NSString: AnyObject] = [
            kSecAttrIsPermanent: true as AnyObject,
            kSecAttrApplicationTag: publicTag as AnyObject
        ]
        // Initializing private key Parameters 
        let privateKeyParameters: [NSString: AnyObject] = [
            kSecAttrIsPermanent: true as AnyObject,
            kSecAttrApplicationTag: publicTag as AnyObject
        ]
        
        // Passing the above generated public & private key into a single parameter with key size and type
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject
        ];
        
        // check status after Key generation
        let status : OSStatus = SecKeyGeneratePair(parameters as CFDictionary, &(self.publicKey), &(self.privateKey))
//        print(privateKey)
        return (status == errSecSuccess && self.publicKey != nil && self.privateKey != nil)
    }
    
    //MARK: - Encrypt Function
    func encrypt(text: String) -> [UInt8] {
        // Cipher parameters
        let plainBuffer = [UInt8](text.utf8)
        var cipherBufferSize : Int = Int(SecKeyGetBlockSize((self.publicKey)!))
        var cipherBuffer = [UInt8](repeating:0, count:Int(cipherBufferSize))
         
        // Encrypto  should less than key length
        let status = SecKeyEncrypt((self.publicKey)!, SecPadding.PKCS1, plainBuffer, plainBuffer.count, &cipherBuffer, &cipherBufferSize)
        if (status != errSecSuccess) {
            print("Failed Encryption")
        }
        return cipherBuffer
    }
    
    //MARK: - decrypt Function
    func decprypt(encrpted: [UInt8]) -> String? {
        var plaintextBufferSize = Int(SecKeyGetBlockSize((self.privateKey)!))
        var plaintextBuffer = [UInt8](repeating:0, count:Int(plaintextBufferSize))
        
        // check status
        let status = SecKeyDecrypt((self.privateKey)!, SecPadding.PKCS1, encrpted, plaintextBufferSize, &plaintextBuffer, &plaintextBufferSize)
        
        if (status != errSecSuccess) {
            print("Failed Decrypt")
            return nil
        }
        return NSString(bytes: &plaintextBuffer, length: plaintextBufferSize, encoding: String.Encoding.utf8.rawValue)! as String
    }
    
    
    func encryptBase64(text: String) -> String {
        // Cipher parameter
        let plainBuffer = [UInt8](text.utf8)
        var cipherBufferSize : Int = Int(SecKeyGetBlockSize((self.publicKey)!))
        var cipherBuffer = [UInt8](repeating:0, count:Int(cipherBufferSize))
        
        // Encrypto  should less than key length
        let status = SecKeyEncrypt((self.publicKey)!, SecPadding.PKCS1, plainBuffer, plainBuffer.count, &cipherBuffer, &cipherBufferSize)
        if (status != errSecSuccess) {
            print("Failed Encryption")
        }
        
        // Encoding to Base64
        let mudata = NSData(bytes: &cipherBuffer, length: cipherBufferSize)
        return mudata.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength64Characters)
    }
    
    func decpryptBase64(encrpted: String) -> String? {
        
        // parameter for decyrpt
        let data : NSData = NSData(base64Encoded: encrpted, options: .ignoreUnknownCharacters)!
        let count = data.length / MemoryLayout<UInt8>.size
        var array = [UInt8](repeating: 0, count: count)
        data.getBytes(&array, length:count * MemoryLayout<UInt8>.size)
        
        var plaintextBufferSize = Int(SecKeyGetBlockSize((self.privateKey)!))
        var plaintextBuffer = [UInt8](repeating:0, count:Int(plaintextBufferSize))
        
        //check status
        let status = SecKeyDecrypt((self.privateKey)!, SecPadding.PKCS1, array, plaintextBufferSize, &plaintextBuffer, &plaintextBufferSize)
        
        if (status != errSecSuccess) {
            print("Failed Decrypt")
            return nil
        }
        return NSString(bytes: &plaintextBuffer, length: plaintextBufferSize, encoding: String.Encoding.utf8.rawValue)! as String
    }
    
    
    //Function to get public key
    func getPublicKey() -> SecKey? {
        return self.publicKey
    }
    
    //Function to get private key
    func getPrivateKey() -> SecKey? {
        return self.privateKey
    }
    
}
