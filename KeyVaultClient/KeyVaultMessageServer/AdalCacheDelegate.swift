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
import ADAL

class AdalCacheDelegate : NSObject, ADTokenCacheDelegate {
    let queue = DispatchQueue(label:"AdalCacheDelegate")
    
    enum KeychainError : Error {
        case NotFound
        case UnhandledError(OSStatus)
    }
    
    private func readFromKeychain() throws -> Data {
        var result: CFTypeRef?
        let status = withUnsafeMutablePointer(to: &result) { (ptr) -> OSStatus in
            let query = [kSecClass : kSecClassGenericPassword,
                         kSecAttrAccount : "LabKeyvault" as CFString,
                         kSecAttrService : "ADALCache" as CFString,
                         kSecReturnData : true as CFBoolean] as [CFString:CFTypeRef]
            return SecItemCopyMatching(query as CFDictionary , ptr)
        }
        
        if status == errSecItemNotFound {
            throw KeychainError.NotFound
        } else if status != errSecSuccess {
            throw KeychainError.UnhandledError(status)
        }
        
        return result as! Data
    }
    
    private func readAndUpdateCache(_ cache:ADTokenCache) throws {
        let data = try readFromKeychain()
        var error: ADAuthenticationError?
        let success = withUnsafeMutablePointer(to: &error) { (ptr) -> Bool in
            // If you're looking at this and thinking "holy &%^* this is amazingly ugly, why the
            // $^#! do we have to do anything even remotely looking like this?" know that this is
            // the cost for subclassing NSError instead of just using NSError directly
            let ugh = AutoreleasingUnsafeMutablePointer<ADAuthenticationError?>(ptr)
            return cache.deserialize(data, error: ugh)
        }
        
        if !success {
            throw error!
        }
    }
    
    private func writeToKeychain(_ data: Data) throws {
        var query = [kSecClass : kSecClassGenericPassword,
                     kSecAttrAccount : "LabKeyvault" as CFString,
                     kSecAttrService : "ADALCache" as CFString] as [CFString : CFTypeRef]
        let update = [kSecValueData : data]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess {
            return
        } else if status != errSecItemNotFound {
            throw KeychainError.UnhandledError(status)
        }
        
        query[kSecValueData] = data as CFTypeRef
        status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecItemNotFound {
            throw KeychainError.NotFound
        } else if status != errSecSuccess {
            throw KeychainError.UnhandledError(status)
        }
    }
    
    func willAccessCache(_ cache: ADTokenCache) {
        queue.sync {
            do {
                try readAndUpdateCache(cache)
            } catch let err {
                Logger.log("willAccessCache failed: \(err)")
            }
        }
    }
    
    func didAccessCache(_ cache: ADTokenCache) {
    }
    
    func willWrite(_ cache: ADTokenCache) {
        queue.sync {
            do {
                try readAndUpdateCache(cache)
            } catch let err {
                Logger.log("willWrite failed: \(err)")
            }
        }
    }
    
    func didWrite(_ cache: ADTokenCache) {
        queue.sync {
            do {
                try writeToKeychain(cache.serialize()!)
            } catch let err {
                Logger.log("didWrite failed: \(err)")
            }
        }
    }
}
