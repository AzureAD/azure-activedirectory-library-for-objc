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

@objc(KVCHTTPConnectionDelegate) protocol HTTPConnectionDelegate : class {
    @objc func connectionClosed(_ connection: HTTPConnection)
}

@objc(KVCHTTPConnection) class HTTPConnection : NSObject, StreamDelegate
{
    enum HTTPConnectionError : Error {
        case FailedToAppendBytesToHTTPMessage
    }
    
    static var connections = [] as [HTTPConnection]
    
    let queue = DispatchQueue(label:"KVCHTTPConnection")
    let readStream : InputStream
    let writeStream : OutputStream
    
    weak var delegate : HTTPConnectionDelegate?
    
    var replies = [] as [Data]
    var currentReply = nil as Data?
    var currentReplyByte = 0
    var currentMessage = HTTPMessage(isRequest:true)
    
    var sentReply = false
    
    @objc init(readStream: InputStream, writeStream: OutputStream, delegate: HTTPConnectionDelegate) {
        self.readStream = readStream
        self.writeStream = writeStream
        CFReadStreamSetDispatchQueue(readStream, queue)
        CFWriteStreamSetDispatchQueue(writeStream, queue)
        
        super.init()
        
        readStream.delegate = self
        writeStream.delegate = self
        self.delegate = delegate
    }
    
    @objc func open() {
        readStream.open()
        writeStream.open()
    }
    
    @objc func close() {
        Logger.log("closing")
        readStream.delegate = nil
        writeStream.delegate = nil
        readStream.close()
        writeStream.close()
        
        self.delegate?.connectionClosed(self)
    }
    
    func readBytes() throws {
        let bufSize = 2048
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        var result = readStream.read(buffer, maxLength: bufSize)
        while (result > 0)
        {
            if (!currentMessage.appendBytes(buffer, result)) {
                throw HTTPConnectionError.FailedToAppendBytesToHTTPMessage
            }
            
            // This is because Swift is (supposedly) not optimized for tail end recursion, so running
            // it in a loop like this removes a recursive call
            while(try checkCurrentMessage()) { }
            
            result = readStream.read(buffer, maxLength: bufSize)
        }
    }
    
    // Returns true if there's a new message to check status on as well
    func checkCurrentMessage() throws -> Bool {
        switch (try currentMessage.checkMessageStatus()) {
        case .HeadersIncomplete, .NoLengthSpecified, .Incomplete:
            // In all of these cases we need to just keep reading off the stream
            break
        case .Complete:
            processMessage(currentMessage)
            currentMessage = HTTPMessage(isRequest: true)
            break
        case .CompleteExtraBytes(let data):
            processMessage(currentMessage)
            currentMessage = HTTPMessage(isRequest: true)
            if (!currentMessage.appendData(data)) {
                throw HTTPConnectionError.FailedToAppendBytesToHTTPMessage
            }
            return true
        }
        
        return false
    }
    
    func processMessage(_ message:HTTPMessage) {
        MessageHandler.shared.processMessage(message) { (err, reply) in
            guard let reply = reply else {
                Logger.log("Request failed with error: \(err)")
                let reply = HTTPMessage(responseCode: 402, statusDescription: "Request Failed")
                reply.setBody("Request failed: \(String(describing: err))".data(using: String.Encoding.utf8)!)
                self.replies.append(reply.toData())
                self.writeBytes()
                return
            }
            
            self.replies.append(reply)
            self.writeBytes()
        }
    }
    
    func writeBytes() {
        if !writeStream.hasSpaceAvailable {
            return
        }
        
        if let currentReply = self.currentReply {
            writeCurrentReply(currentReply)
            return
        }
        
        if (replies.count == 0) {
            
            // The most likely side effect of this right now is that if for some reason we got multiple HTTP requests
            // on the same connection, we'd only end up responding to one of them. I'm not aware of a situation where
            // this will be a problem for how this code is used now, but if someone goes crazy with it in the future
            // that might become a problem. So if you're investigating something that looks like that, start with this
            // sent reply thing, you'll probably need to have some flag as well that keeps track of whether or not
            // you've received all of the requests yet (?????) then again I could just be crazy
            if (sentReply) {
                close()
            }
            
            return
        }
        
        self.currentReply = replies.removeFirst()
        writeCurrentReply(self.currentReply!)
    }
    
    func writeCurrentReply(_ data:Data) {
        Logger.log("writing output")
        
        let bytesRemaining = data.count - currentReplyByte
        let bytesWritten = data.withUnsafeBytes { (ptr) -> Int in
            return writeStream.write(ptr + currentReplyByte, maxLength:bytesRemaining)
        }
        
        Logger.log("wrote \(bytesWritten) bytes to output")
        
        if bytesWritten == bytesRemaining {
            self.currentReply = nil
            currentReplyByte = 0
            sentReply = true
            writeBytes()
        } else {
            currentReplyByte = bytesWritten
        }
    }
    
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        Logger.log("Stream event \(eventCode)")
        
        do {
            switch eventCode {
            case .openCompleted:
                break
            case .hasBytesAvailable:
                try readBytes()
            case .hasSpaceAvailable:
                writeBytes()
            case .errorOccurred:
                Logger.log("Connected error occurred: \(String(describing: aStream.streamError))")
            case .endEncountered:
                Logger.log("End encountered")
                try readBytes()
                if aStream == writeStream {
                    close()
                }
            default:
                Logger.log("unknown event code (\(eventCode))")
            }
        } catch let err {
            Logger.log("\(err)")
        }
    }
}
