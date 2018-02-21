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

#import "ADRefreshResponseBuilder.h"
#import "ADTestConstants.h"

@implementation ADRefreshResponseBuilder

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    self.authority = TEST_AUTHORITY;
    self.clientId = TEST_CLIENT_ID;
    self.resource = TEST_RESOURCE;
    
    self.oldRefreshToken = TEST_REFRESH_TOKEN;
    self.updatedAccessToken = TEST_ACCESS_TOKEN;
    self.updatedRefreshToken = TEST_UPDATE_REFRESH_TOKEN;
    self.expirationTime = [NSDate dateWithTimeIntervalSinceNow:3600.0];
    
    self.correlationId = TEST_CORRELATION_ID;
    
    _requestHeaders = [[ADTestURLResponse defaultHeaders] mutableCopy];
    _requestBody = [NSMutableDictionary new];
    
    _responseHeaders = [NSMutableDictionary new];
    _responseBody = [NSMutableDictionary new];
    
    self.responseCode = 200;
    
    return self;
}

- (nonnull ADTestURLResponse *)response
{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, self.authority];
    
    _requestHeaders[@"client-request-id"] = [self.correlationId UUIDString];
    
    NSMutableDictionary *requestBody = [NSMutableDictionary new];
    requestBody[MSID_OAUTH2_GRANT_TYPE] = @"refresh_token";
    requestBody[MSID_OAUTH2_REFRESH_TOKEN] = self.oldRefreshToken;
    requestBody[MSID_OAUTH2_RESOURCE] = self.resource;
    requestBody[MSID_OAUTH2_CLIENT_ID] = self.clientId;
    [requestBody addEntriesFromDictionary:_requestBody];
    
    NSMutableDictionary *responseBody = [NSMutableDictionary new];
    responseBody[MSID_OAUTH2_REFRESH_TOKEN] = self.updatedRefreshToken;
    responseBody[MSID_OAUTH2_ACCESS_TOKEN] = self.updatedAccessToken;
    responseBody[MSID_OAUTH2_RESOURCE] = self.resource;
    [responseBody addEntriesFromDictionary:_responseBody];
    if (_updatedIdToken) {
        responseBody[MSID_OAUTH2_ID_TOKEN] = _updatedIdToken;
    }
    
    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:_requestHeaders
                      requestParamsBody:requestBody
                      responseURLString:@"https://contoso.com"
                           responseCode:self.responseCode
                       httpHeaderFields:_responseHeaders
                       dictionaryAsJSON:responseBody];
    
    return response;
}

@end
