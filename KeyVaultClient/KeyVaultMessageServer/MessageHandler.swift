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

import Foundation
import KeyVault

@objc(KVCMessageHandler) class MessageHandler : NSObject {
    @objc static let shared = MessageHandler()
    static let badMessageReply = HTTPMessage(responseCode:400, statusDescription: "Bad Message").toData()
    
    struct SecretRequest : Codable {
        let url : String
    }
    
    @objc public func processMessage(_ message:HTTPMessage, _ completion:@escaping (Error?, Data?) -> Void) {
        if (message.method != "POST") {
            completion(nil, MessageHandler.badMessageReply)
            return
        }
        
        guard let data = message.body() else {
            completion(nil, MessageHandler.badMessageReply)
            return
        }
        
        do {
            let req = try JSONDecoder().decode(SecretRequest.self, from: data);
            Logger.log("Requesting secret: \(req.url)")
            KeyVault.Secret.get(URL(string:req.url)!) { (result) in
                switch (result) {
                case .Success(let secret) :
                    let reply = HTTPMessage(responseCode:200, statusDescription: "OK")
                    reply.setBody("{\"secret\":\"\(secret.value)\"}".data(using: String.Encoding.utf8)!)
                    completion(nil, reply.toData())
                case .Failure(let err) :
                    completion(err, nil)
                }
            }
        }
        catch let err {
            Logger.log("\(err)")
            return completion(err, nil)
        }
    }
}
