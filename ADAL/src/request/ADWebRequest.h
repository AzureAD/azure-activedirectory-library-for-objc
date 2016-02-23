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

@class ADWebRequest;
@class ADWebResponse;

extern NSString *const HTTPGet;
extern NSString *const HTTPPost;

@interface ADWebRequest : NSObject <NSURLConnectionDelegate>
{
    NSURLConnection * _connection;
    
    NSURL * _requestURL;
    NSString* _requestMethod;
    NSMutableDictionary* _requestHeaders;
    NSData * _requestData;
    
    NSHTTPURLResponse * _response;
    NSMutableData * _responseData;
    
    NSUUID * _correlationId;
    
    NSUInteger _timeout;
    
    NSOperationQueue * _operationQueue;
    
    void (^_completionHandler)( NSError *, ADWebResponse *);
}

@property (strong, readonly, nonatomic) NSURL               *URL;
@property (strong)                      NSString            *method;
@property (strong, readonly, nonatomic) NSMutableDictionary *headers;
@property (strong)                      NSData              *body;
@property (nonatomic)           NSUInteger           timeout;

- (id)initWithURL: (NSURL*)url
    correlationId: (NSUUID*) correlationId;

- (void)send:( void (^)( NSError *, ADWebResponse *) )completionHandler;

@end

