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

#include <netinet/in.h>
#include <netdb.h>

#import "KeyVaultMessageServer-Swift.h"

#import "KVCMessageServer.h"

@interface KVCMessageServer () <KVCHTTPConnectionDelegate>
- (void)openConnection:(CFSocketNativeHandle)soc;
@end

static void KVCServerHandleConnect(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info)
{
    if (type != kCFSocketAcceptCallBack)
    {
        NSLog(@"Unexpected socket callback type");
        return;
    }
    
    CFSocketNativeHandle soc = *(CFSocketNativeHandle *)data;
    [(__bridge KVCMessageServer *)info openConnection:soc];
}

@implementation KVCMessageServer
{
    CFSocketRef _socket;
    NSMutableArray<KVCHTTPConnection *> *_connections;
}

+ (instancetype)shared
{
    static dispatch_once_t onceToken;
    static KVCMessageServer *server = nil;
    dispatch_once(&onceToken, ^{
        server = [KVCMessageServer new];
    });
    
    return server;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _connections = [NSMutableArray new];
    
    return self;
}

- (BOOL)start
{
    [KVCLogger log:@"Starting Message Server"];
    CFSocketContext context = {0, (__bridge void *)(self), CFRetain, CFRelease, CFCopyDescription};
    _socket = CFSocketCreate(NULL, 0, 0, 0, kCFSocketAcceptCallBack, &KVCServerHandleConnect, &context);
    if (!_socket)
    {
        [KVCLogger log:@"Unable to create CFSocket"];
        return NO;
    }
    
    struct sockaddr_in sin;
    
    struct hostent *host = gethostbyname("localhost");
    unsigned int port = 59127;
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET; /* Address family */
    sin.sin_port = htons(port); /* Or a specific port */
    memcpy(&(sin.sin_addr), host->h_addr,host->h_length);
    
    CFDataRef cfdAddress = CFDataCreate(kCFAllocatorDefault, (UInt8*)&sin, sizeof(sin));
    if (!cfdAddress)
    {
        [KVCLogger log:@"Failed to create address data blob."];
        return NO;
    }
    
    [KVCLogger log:[NSString stringWithFormat:@"Listing on port %u", port]];
    
    if (CFSocketSetAddress(_socket, cfdAddress) != kCFSocketSuccess)
    {
        [KVCLogger log:@"Failed to set address on socket."];
        return NO;
    }
    
    CFRunLoopSourceRef src = CFSocketCreateRunLoopSource(kCFAllocatorDefault, _socket, 0);
    if (!src)
    {
        [KVCLogger log:@"Failed to create run loop source."];
        return NO;
    }
    
    CFRunLoopAddSource(CFRunLoopGetCurrent(), src, kCFRunLoopDefaultMode);
    [KVCLogger log:@"Server Started"];
    return NO;
}

- (void)stop
{
    CFSocketInvalidate(_socket);
    _socket = NULL;
}

- (void)openConnection:(CFSocketNativeHandle)soc
{
    CFReadStreamRef readStream = NULL;
    CFWriteStreamRef writeStream = NULL;
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, soc, &readStream, &writeStream);
    if (!readStream || !writeStream)
    {
        close(soc);
        [KVCLogger log:@"Failed to create read and write streams for connection"];
        return;
    }
    
    CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    
    __auto_type conn =
    [[KVCHTTPConnection alloc] initWithReadStream:CFBridgingRelease(readStream)
                                      writeStream:CFBridgingRelease(writeStream)
                                         delegate:self];
    [conn open];
    [_connections addObject:conn];
}

- (void)connectionClosed:(KVCHTTPConnection * _Nonnull)connection {
    [_connections removeObject:connection];
}

@end
