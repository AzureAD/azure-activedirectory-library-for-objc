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

@objc public class Secret : NSObject {
    override public var description: String {
        return "\(name) : \(value)"
    }
    
    @objc public let name : String
    public let url : URL
    @objc public let value : String
    
    public let updated : Date
    public let created : Date
    
    internal init(_ url: URL, _ value: String, _ created: Int, _ updated: Int) {
        self.name = url.lastPathComponent
        self.url = url
        self.value = value
        self.updated = Date(timeIntervalSince1970: Double(updated))
        self.created = Date(timeIntervalSince1970: Double(created))
    }
    
    @objc public class func get(url: URL, completion: @escaping (NSError?, Secret?) -> Void) {
        self.get(url) { (result) in
            switch result {
            case .Failure(let err) :
                let userInfo = ["description" : err.localizedDescription,
                                "value" : String(describing:err)]
                completion(NSError(domain: String(describing:err.self) + "Domain", code:0, userInfo:userInfo), nil)
            case .Success(let secret) :
                completion(nil, secret)
            }
        }
    }
    
    public class func get(_ url: URL,_ completion: @escaping (Result<Secret>) -> Void) {
        Network.getSecret(url.absoluteString, completion)
    }
    
    public class func getList(_ server: URL, _ completion: @escaping (Result<[URL]>) -> Void) {
        Network.getSecretList(server, completion)
    }
}
