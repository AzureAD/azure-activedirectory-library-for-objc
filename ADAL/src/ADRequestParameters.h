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

#import "ADTokenCacheDataSource.h"
#import "ADRequestContext.h"

@class ADTokenCacheAccessor;

@interface ADRequestParameters : NSObject <ADRequestContext>
{
    NSString *_authority;
    NSString *_resource;
    NSString *_clientId;
    NSString *_redirectUri;
    NSString *_scope;
    ADUserIdentifier *_identifier;
    ADTokenCacheAccessor *_tokenCache;
    BOOL _extendedLifetime;
    BOOL _forceRefresh;
    NSUUID *_correlationId;
    NSString *_telemetryRequestId;
}

@property (retain, nonatomic) NSString* authority;
@property (retain, nonatomic) NSString* resource;
@property (retain, nonatomic) NSString* clientId;
@property (retain, nonatomic) NSString* redirectUri;
@property (retain, nonatomic) NSString* scope;
@property (retain, nonatomic) NSString* claims;
@property (retain, nonatomic) ADUserIdentifier* identifier;
@property (retain, nonatomic) ADTokenCacheAccessor* tokenCache;
@property BOOL extendedLifetime;
@property BOOL forceRefresh;
@property (retain, nonatomic) NSUUID* correlationId;
@property (retain, nonatomic) NSString* telemetryRequestId;

- (id)initWithAuthority:(NSString *)authority
               resource:(NSString *)resource
               clientId:(NSString *)clientId
            redirectUri:(NSString *)redirectUri
             identifier:(ADUserIdentifier *)identifier
             tokenCache:(ADTokenCacheAccessor *)tokenCache
       extendedLifetime:(BOOL)extendedLifetime
          correlationId:(NSUUID *)correlationId
     telemetryRequestId:(NSString *)telemetryRequestId;

@end
