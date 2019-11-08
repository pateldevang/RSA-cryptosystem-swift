//
//  ViewController.swift
//  RSA
//
//  Created by Devang Patel on 01/11/19.
//  Copyright © 2019 Devang Patel. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    
    //MARK: - Outlets
    @IBOutlet weak var text: UITextField!
    @IBOutlet weak var qrimage: UIImageView!
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        //MARK: - Testing
        let rsa : RSAWrapper? = RSAWrapper()
        let success : Bool = (rsa?.generateKeyPair(keySize: 2048, privateTag: "in.devangpatel", publicTag: "in.devangpatel"))!
        if (!success) {
            print("Failed")
            return
        }
        let test : String = "PID001"
        let encryption = rsa?.encryptBase64(text: test)
        print(encryption as Any)
        let decription = rsa?.decpryptBase64(encrpted: encryption!)
        print(decription as Any)
        
    }

    

    @IBAction func generateAction(_ sender: Any) {
        // Setting up RSA wrapper
        let rsa : RSAWrapper? = RSAWrapper()
        let success : Bool = (rsa?.generateKeyPair(keySize: 2048, privateTag: "in.devangpatel", publicTag: "in.devangpatel"))!
        if (!success) {
            print("Failed")
            return
        }
        let test : String = text.text!
        let encryption = rsa?.encryptBase64(text: test)
        print(encryption as Any)
        qrimage.image = generateQRCode(from: "\(String(describing: encryption))")
        //text.text = ""
    }
    
    
    //MARK: - Generate QR function
    func generateQRCode(from string: String) -> UIImage? {
        let data = string.data(using: String.Encoding.ascii)
        
        if let filter = CIFilter(name: "CIQRCodeGenerator") {
            filter.setValue(data, forKey: "inputMessage")
            let transform = CGAffineTransform(scaleX: 3, y: 3)
            
            if let output = filter.outputImage?.transformed(by: transform) {
                return UIImage(ciImage: output)
            }
        }
        
        return nil
    }
    
    
}

