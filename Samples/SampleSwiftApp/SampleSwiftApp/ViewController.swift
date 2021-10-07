// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import UIKit
import ADAL

class ViewController: UIViewController {
    
    @IBOutlet weak var statusTextField: UITextView?

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    func updateStatusField(_ text: String)
    {
        guard Thread.isMainThread else {
            
            DispatchQueue.main.async {
                self.updateStatusField(text)
            }
            
            return
        }
        
        statusTextField?.text = text;
    }
    
    @IBAction func acquireToken(_ sender:UIButton) {
        
        guard let authContext = ADALAuthenticationContext(authority: "https://login.microsoftonline.com/common", error: nil) else {
            
            print("Failed to create auth context")
            return
        }
        
        authContext.acquireToken(withResource: "https://graph.windows.net",
                                 clientId: "b92e0ba5-f86e-4411-8e18-6b5f928d968a",
                                 redirectUri: URL(string: "urn:ietf:wg:oauth:2.0:oob")!)
        {
            [weak self] (result) in
            
            guard let weakself = self else { return }
            
            guard result.status == AD_SUCCEEDED else {
                
                if result.error!.domain == ADAuthenticationErrorDomain
                    && result.error!.code == ADALErrorCode.AD_ERROR_UNEXPECTED.rawValue {
                    
                    weakself.updateStatusField("Unexpected internal error occured")
                }
                else {
                    weakself.updateStatusField(result.error!.description)
                }
                
                return
            }
            
            var expiresOnString = "(nil)"
            
            guard let tokenCacheItem = result.tokenCacheItem else {
                weakself.updateStatusField("No token cache item returned")
                return
            }
            
            expiresOnString = String(describing: tokenCacheItem.expiresOn)
            
            let status = String(format: "Access token: %@\nexpiration:%@", result.accessToken!, expiresOnString)
            weakself.updateStatusField(status)
        }
    }
}

