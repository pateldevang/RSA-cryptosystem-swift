//
//  ViewController.swift
//  RSA
//
//  Created by Devang Patel on 01/11/19.
//  Copyright © 2019 Devang Patel. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        //MARK: - Testing
        let rsa : RSAWrapper? = RSAWrapper()
        let success : Bool = (rsa?.generateKeyPair(keySize: 2048, privateTag: "in.devangpatel", publicTag: "in.devangpatel"))!
        if (!success) {
            print("Failed")
            return
        }
        let test : String = "You can't see me!"
        let encryption = rsa?.encryptBase64(text: test)
        print(encryption)
        let decription = rsa?.decpryptBase64(encrpted: encryption!)
        print(decription)
        
    }


}

