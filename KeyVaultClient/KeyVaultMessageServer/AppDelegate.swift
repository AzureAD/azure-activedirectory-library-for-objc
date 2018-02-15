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

import Cocoa
import ADAL
import KeyVault

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    private static let clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    private static let redirectUri = URL(string: "urn:ietf:wg:oauth:2.0:oob")!
    
    @IBOutlet weak var window: NSWindow!
    @IBOutlet weak var textView: NSTextView!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        ADLogger.setLoggerCallback { (level, log, pii) in
            Logger.log(log!)
        }
        
        Logger.logCallback = { (string) in
            DispatchQueue.main.async {
                self.textView.textStorage?.append(NSAttributedString(string:string + "\n"))
            }
            
            print(string)
        }
        
        ADAuthenticationSettings.sharedInstance().defaultStorageDelegate = AdalCacheDelegate()
        
        KeyVault.Authentication.authCallback = { (authority, resource, callback) in
            let authContext = ADAuthenticationContext(authority: authority,
                                                      error: nil)
            
            authContext!.acquireTokenSilent(withResource: resource, clientId: AppDelegate.clientId, redirectUri: AppDelegate.redirectUri) { (result) in
                let result = result!
                
                if result.status == AD_SUCCEEDED {
                    Logger.log("Acquired token silently")
                    DispatchQueue.global().async {
                        callback(.Success(result.accessToken))
                    }
                    return
                }
                
                DispatchQueue.main.async {
                    authContext!.acquireToken(withResource: resource, clientId: AppDelegate.clientId, redirectUri: AppDelegate.redirectUri) { (result) in
                        let result = result!
                        
                        if result.status != AD_SUCCEEDED {
                            callback(.Failure(result.error!))
                        } else {
                            Logger.log("Acquired token")
                            callback(.Success(result.accessToken))
                        }
                    }
                }
            }
        }
        
        KVCMessageServer.shared().start()
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
        KVCMessageServer.shared().stop()
    }

}

