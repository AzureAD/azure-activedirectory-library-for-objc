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

class Network {
    static let apiVersion = "2016-10-01"
    
    struct SecretInfo : Codable {
        let id: String
    }
    
    struct SecretResponse : Codable {
        let value: [SecretInfo]
    }
    
    private class func processSecretListJson(_ data: Data) -> Result<[SecretInfo]> {
        do {
            let decoder = JSONDecoder()
            let response = try decoder.decode(SecretResponse.self, from: data)
            return .Success(response.value)
        } catch let err {
            print("Failed to parse secret list: \(err)")
            return .Failure(err)
        }
    }
    
    private class func getSecretList(_ reqUrl:URL, _ token:String,_ completion: @escaping (Result<[SecretInfo]>) -> Void) {
        var req = URLRequest(url: reqUrl)
        req.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        print("Getting secret list")
        URLSession.shared.dataTask(with: req) { (data, response, error) in
            if let error = error {
                print("Failed to get secrets: \(error)")
                completion(.Failure(error))
                return
            }
            print("Parsing secrets")
            completion(processSecretListJson(data!))
        }.resume()
    }
    
    private class func processSecretList(_ result:Result<[SecretInfo]>) -> Result<[URL]> {
        switch result {
        case .Failure(let err) : return .Failure(err)
        case .Success(let list) :
            var urls = [] as [URL]
            for secret in list {
                guard let url = URL(string:secret.id) else {
                    return .Failure(KeyVaultError.InvalidUrl)
                }
                
                urls.append(url)
            }
            return .Success(urls)
        }
    }
    
    internal class func getSecretList(_ server:URL,_ completion: @escaping (Result<[URL]>) -> Void) {
        var reqUrl = URL(string:"secrets?api-version=\(apiVersion)", relativeTo:server)!
        reqUrl = URL(string:reqUrl.absoluteString)!
        
        Authentication.getToken(reqUrl) { (result) in
            switch (result) {
            case .Success(let token) : getSecretList(reqUrl, token) { (result) in completion(processSecretList(result))}
            case .Failure(let err) : completion(.Failure(err))
            }
        }
    }
    
    struct SecretAttributes : Codable {
        let updated: Int
        let created: Int
    }
    
    struct SecretValue : Codable {
        let value : String
        let attributes : SecretAttributes
    }
    
    private class func processSecretJson(_ data: Data) -> Result<SecretValue> {
        do {
            let decoder = JSONDecoder()
            let response = try decoder.decode(SecretValue.self, from: data)
            return .Success(response)
        } catch let err {
            return .Failure(err)
        }
    }
    
    private class func getSecret(_ url:URL, _ token: String, _ completion:@escaping (Result<Secret>) -> Void) {
        var req = URLRequest(url: url)
        req.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        print("Getting \(url.lastPathComponent) secret from \(url.host!)")
        URLSession.shared.dataTask(with: req) { (data, response, error) in
            // Using sync here allows the operation to occur on our current thread without
            // requiring further thread switching
            if let error = error {
                completion(.Failure(error))
                return
            }
            
            let result = processSecretJson(data!)
            switch result {
            case .Success(let value) : completion(.Success(Secret(url, value.value, value.attributes.created, value.attributes.updated)))
            case .Failure(let error) : completion(.Failure(error))
            }
        }.resume()
    }
    
    internal class func getSecret(_ id: String, _ completion:@escaping (Result<Secret>) -> Void) {
        let url = URL(string: "\(id)?api-version=\(apiVersion)")!
        Authentication.getToken(url) { (result) in
            switch result {
            case .Success(let token) : getSecret(url, token, completion)
            case .Failure(let error) : completion(.Failure(error))
            }
        }
    }
}
