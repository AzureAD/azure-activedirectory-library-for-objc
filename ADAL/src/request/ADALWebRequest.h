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

#import "MSIDRequestContext.h"

@class ADALWebRequest;
@class ADALWebResponse;

typedef void (^ADALWebResponseCallback)(ADALAuthenticationError *, NSMutableDictionary *);

@interface ADALWebRequest : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate, MSIDRequestContext>
{
    NSURLSessionDataTask * _task;
    
    NSURLSession *_session;
    
    NSURL * _requestURL;
    NSMutableDictionary* _requestHeaders;
    NSData * _requestData;
    
    NSHTTPURLResponse * _response;
    NSMutableData * _responseData;
    
    NSUUID * _correlationId;
    
    NSUInteger _timeout;
    
    BOOL _isGetRequest;
    
    NSString* _telemetryRequestId;
    
    void (^_completionHandler)( NSError *, ADALWebResponse *);
}

@property (strong, readonly, nonatomic) NSURL               *URL;
@property (strong)                      NSData              *body;
@property (nonatomic)                   NSUInteger           timeout;
@property BOOL isGetRequest;
@property (readonly) NSUUID *correlationId;
@property (readonly) NSString *telemetryRequestId;
@property (readonly) NSString *logComponent;
@property (nonatomic) NSDictionary *appRequestMetadata;

@property (atomic, strong, readonly) NSURLSession *session;

- (id)initWithURL:(NSURL *)url
          context:(id<MSIDRequestContext>)context;

- (void)send:( void (^)( NSError *, ADALWebResponse *) )completionHandler;

- (void)addToHeadersFromDictionary:(NSDictionary *)headers;
- (void)setAuthorizationHeader:(NSString *)header;

/*!
    Resends a request. Note, this will cause the completionHandler previously set
    in -send: to be hit again. As such this method should only be called from
    within the completionHandler block on -send:
 */
- (void)resend;

/*!
    Invalidates session object and nils the completionHandler.
    Caller must invoke this method once it's done with the session.
    Do not use send or resend after calling invalidate.
 */
- (void)invalidate;

@end

