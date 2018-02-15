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

public class Authentication {
    private static let paramsQueue = DispatchQueue(label:"AuthParams")
    private static var paramCache = [:] as [String : AuthParameters]
    
    private class AuthParameters {
        let authority : String
        let resource : String
        
        init(_ authority: String, _ resource: String) {
            self.authority = authority
            self.resource = resource
        }
    }
    
    public typealias AuthCallback = (_ authority:String, _ resource:String, _ callback: @escaping (Result<String>) -> Void) -> Void
    
    public static var authCallback : AuthCallback?
    
    private class func getToken(_ server:URL, _ params:AuthParameters, _ completion: @escaping (Result<String>) -> Void) {
        guard let authCallback = Authentication.authCallback else {
            completion(.Failure(KeyVaultError.NoAuthCallback))
            return
        }
        
        authCallback(params.authority, params.resource, completion)
    }
    
    private class func getValue(_ dict:[Substring : Substring], _ possibleKeys:[String]) throws -> Substring {
        for key in possibleKeys {
            if let val = dict[Substring(key)] {
                return val
            }
        }
        
        throw KeyVaultError.BearerChallengeMissingRequiredParameter
    }
    
    private class func getAuthParams(_ server:URL, _ completion: @escaping (Result<AuthParameters>) -> Void) {
        print("Getting auth parameters for \(server)")
        URLSession.shared.dataTask(with: server) { (data, response, error) in
            if let error = error {
                completion(.Failure(error))
                return
            }
            
            let response = response as! HTTPURLResponse
            let headers = response.allHeaderFields
            
            guard let authHeader = headers["Www-Authenticate"] as? String else {
                // fail
                completion(.Failure(KeyVaultError.NoAuthHeader))
                return
            }
            
            do {
                let challenges = try AuthHeader.parse(authHeader)
                
                guard let bearer = challenges["Bearer"] else {
                    throw KeyVaultError.NoBearerChallenge
                }
                
                let authority = try getValue(bearer, ["authorization_uri", "authorization"])
                let resource = try getValue(bearer, ["resource", "resource_id"])
                let params = AuthParameters(String(authority), String(resource))
                paramCache[server.host!] = params
                
                completion(.Success(params))
            } catch (let err) {
                completion(.Failure(err))
                return
            }
        }.resume()
    }
    
    internal class func getToken(_ server:URL, _ completion: @escaping (Result<String>) -> Void) {
        var authParams = nil as AuthParameters?
        paramsQueue.sync {
            authParams = paramCache[server.host!]
        }
        
        if let authParams = authParams {
            getToken(server, authParams, completion)
            return
        }
        
        getAuthParams(server) { (result) in
            switch result {
            case .Success(let params) : getToken(server, params, completion)
            case .Failure(let err) : completion(.Failure(err))
            }
        }
    }
}
