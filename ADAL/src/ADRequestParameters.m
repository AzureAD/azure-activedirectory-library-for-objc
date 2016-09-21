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

#import "ADRequestParameters.h"

@implementation ADRequestParameters

@synthesize authority = _authority;
@synthesize resource = _resource;
@synthesize clientId = _clientId;
@synthesize redirectUri = _redirectUri;
@synthesize identifier = _identifier;
@synthesize tokenCache = _tokenCache;
@synthesize extendedLifetime = _extendedLifetime;
@synthesize correlationId = _correlationId;
@synthesize telemetryRequestId = _telemetryRequestId;

- (id)initWithAuthority:(NSString *)authority
               resource:(NSString *)resource
               clientId:(NSString *)clientId
            redirectUri:(NSString *)redirectUri
             identifier:(ADUserIdentifier *)identifier
             tokenCache:(ADTokenCacheAccessor *)tokenCache
       extendedLifetime:(BOOL)extendedLifetime
          correlationId:(NSUUID *)correlationId
     telemetryRequestId:(NSString *)telemetryRequestId
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    [self setAuthority:authority];
    [self setResource:resource];
    [self setClientId:clientId];
    [self setRedirectUri:redirectUri];
    [self setIdentifier:identifier];
    [self setTokenCache:tokenCache];
    [self setExtendedLifetime:extendedLifetime];
    [self setCorrelationId:correlationId];
    [self setTelemetryRequestId:telemetryRequestId];
    
    return self;
}

- (void)setResource:(NSString *)resource
{
    SAFE_ARC_RELEASE(_resource);
    _resource = [resource adTrimmedString];
    SAFE_ARC_RETAIN(_resource);
}

- (void)setClientId:(NSString *)clientId
{
    SAFE_ARC_RELEASE(_clientId);
    _clientId = [clientId adTrimmedString];
    SAFE_ARC_RETAIN(_clientId);
}

- (void)setRedirectUri:(NSString *)redirectUri
{
    SAFE_ARC_RELEASE(_redirectUri);
    _redirectUri = [redirectUri adTrimmedString];
    SAFE_ARC_RETAIN(_redirectUri);
}

- (void)dealloc
{
    self.authority = nil;
    self.resource = nil;
    self.clientId = nil;
    self.redirectUri = nil;
    self.identifier = nil;
    self.tokenCache = nil;
    self.correlationId = nil;
    self.telemetryRequestId = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

@end