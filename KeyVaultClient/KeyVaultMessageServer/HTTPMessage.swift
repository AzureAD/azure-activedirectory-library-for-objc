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

// Swift convenience wrapper around CFHTTPMessage

import Foundation

@objc(KVCHTTPMessage) class HTTPMessage : NSObject {
    enum HTTPMessageError : Error {
        case InvalidContentLength(String)
    }
    
    let message : CFHTTPMessage
    var method : String? { return CFHTTPMessageCopyRequestMethod(message)?.takeRetainedValue() as String? }
    
    init(isRequest:Bool) {
        message = CFHTTPMessageCreateEmpty(nil, isRequest).takeRetainedValue()
    }
    
    init(requestMethod: String, url: URL) {
        message = CFHTTPMessageCreateRequest(nil, requestMethod as CFString, url as CFURL, kCFHTTPVersion1_1).takeRetainedValue()
    }
    
    init(responseCode:CFIndex, statusDescription: String) {
        message = CFHTTPMessageCreateResponse(nil, responseCode, statusDescription as CFString, kCFHTTPVersion1_1).takeRetainedValue()
    }
    
    func appendBytes(_ bytes:UnsafePointer<UInt8>, _ numBytes:CFIndex) -> Bool {
        return CFHTTPMessageAppendBytes(message, bytes, numBytes)
    }
    
    func appendData(_ data:Data) -> Bool {
        return data.withUnsafeBytes { (ptr) -> Bool in
            return CFHTTPMessageAppendBytes(message, ptr, data.count)
        }
    }
    
    func isHeaderComplete() -> Bool {
        return CFHTTPMessageIsHeaderComplete(message)
    }
    
    func headerFieldValue(_ key:String) -> String? {
        return CFHTTPMessageCopyHeaderFieldValue(message, key as CFString)?.takeUnretainedValue() as String?
    }
    
    enum MessageStatus {
        // We have not seen all of the bytes for the HTTP headers yet
        case HeadersIncomplete
        // In this case the body isn't compelete until the connection is closed
        case NoLengthSpecified
        // The number of bytes has been specified, but the body isn't long enough yet
        case Incomplete
        // This is a complete message with no extra bytes
        case Complete
        // If we have more bytes in the body then the content length that means we got the start
        // of the next message. The bytes in this case code are the next message (and potentially
        // the one after that...)
        case CompleteExtraBytes(Data)
    }
    
    func checkMessageStatus() throws -> MessageStatus {
        if (!isHeaderComplete()) {
            return .HeadersIncomplete
        }
        
        guard let strLength = headerFieldValue("Content-Length") else {
            return .NoLengthSpecified
        }
        
        guard let contentLength = Int(strLength) else {
            throw HTTPMessageError.InvalidContentLength(strLength)
        }
        
        if contentLength < 0 {
            throw HTTPMessageError.InvalidContentLength(strLength)
        }
        
        guard let body = body() else {
            if contentLength == 0 {
                return .Complete
            } else {
                return .Incomplete
            }
        }
        
        let cbBody = body.count
        if (cbBody == contentLength) {
            return .Complete
        }
        
        if (cbBody < contentLength) {
            return .Incomplete
        }
        
        let extraBytes = Data(body[contentLength..<cbBody])
        CFHTTPMessageSetBody(message, Data(body[0..<contentLength]) as CFData)
        
        return .CompleteExtraBytes(extraBytes)
    }
    
    func setBody(_ data:Data) {
        CFHTTPMessageSetBody(message, data as CFData)
    }
    
    func body() -> Data? {
        return CFHTTPMessageCopyBody(message)?.takeRetainedValue() as Data?
    }
    
    func toData() -> Data {
        return CFHTTPMessageCopySerializedMessage(message)!.takeRetainedValue() as Data
    }
}
