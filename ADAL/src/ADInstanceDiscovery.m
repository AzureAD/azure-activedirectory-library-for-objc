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

#import "ADAL_Internal.h"
#import "ADInstanceDiscovery.h"
#import "ADAuthenticationError.h"
#import "ADWebRequest.h"
#import "ADAuthenticationError.h"
#import "NSDictionary+ADExtensions.h"
#import "ADWebResponse.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"
#import "NSString+ADHelperMethods.h"
#import "ADClientMetrics.h"
#import "ADUserIdentifier.h"
#import "ADAuthorityValidation.h"
#import "ADHelpers.h"

static NSString* const sTrustedAuthority = @"https://login.windows.net";
static NSString* const sApiVersionKey = @"api-version";
static NSString* const sApiVersion = @"1.0";
static NSString* const sAuthorizationEndPointKey = @"authorization_endpoint";
//static NSString* const sTenantDiscoveryEndpoint = @"tenant_discovery_endpoint";

//static NSString* const sValidationServerError = @"The authority validation server returned an error: %@.";

@implementation ADInstanceDiscovery

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }

    return self;
}

+ (ADInstanceDiscovery*)sharedInstance
{
    API_ENTRY;
    static dispatch_once_t once;
    static ADInstanceDiscovery* singleton = nil;
    
    dispatch_once(&once, ^{
        singleton = [[ADInstanceDiscovery alloc] init];
    });
    
    return singleton;
}



- (void)validateAuthority:(NSString *)authority
            requestParams:(ADRequestParameters*)requestParams
          completionBlock:(ADDiscoveryCallback)completionBlock;
{
    NSUUID *correlationId = [requestParams correlationId];
    NSString *telemetryRequestId = [requestParams telemetryRequestId];
    THROW_ON_NIL_ARGUMENT(correlationId);//Should be set by the caller
    THROW_ON_NIL_ARGUMENT(correlationId);//Should be set by the caller
    
    ADAuthorityValidation *authorityValidation = [ADAuthorityValidation sharedInstance];
    authorityValidation.correlationId = correlationId;
    authorityValidation.telemetryRequestId = telemetryRequestId;
    
    NSString* message = [NSString stringWithFormat:@"Attempting to validate the authority: %@; CorrelationId: %@", authority, [correlationId UUIDString]];
    AD_LOG_VERBOSE(@"Instance discovery", [requestParams correlationId], message);
    
    NSString *upn = requestParams.identifier.userId;
    
    [authorityValidation validateAuthority:authority upn:upn completionBlock:completionBlock];
}


//Sends authority validation to the trustedAuthority by leveraging the instance discovery endpoint
//If the authority is known, the server will set the "tenant_discovery_endpoint" parameter in the response.
//The method should be executed on a thread that is guarranteed to exist upon completion, e.g. the UI thread.
- (void)requestValidationOfAuthority:(NSString *)authority
                                host:(NSString *)authorityHost
                    trustedAuthority:(NSString *)trustedAuthority
                       requestParams:(ADRequestParameters*)requestParams
                     completionBlock:(ADDiscoveryCallback)completionBlock
{
    (void)trustedAuthority;
    
    NSUUID *correlationId = [requestParams correlationId];
    NSString *telemetryRequestId = [requestParams telemetryRequestId];
    THROW_ON_NIL_ARGUMENT(correlationId);//Should be set by the caller
    THROW_ON_NIL_ARGUMENT(correlationId);//Should be set by the caller
    
    ADAuthorityValidation *authorityValidation = [ADAuthorityValidation sharedInstance];
    authorityValidation.correlationId = correlationId;
    authorityValidation.telemetryRequestId = telemetryRequestId;
    
    NSString* message = [NSString stringWithFormat:@"Attempting to validate the authority: %@; CorrelationId: %@", authority, [correlationId UUIDString]];
    AD_LOG_VERBOSE(@"Instance discovery", [requestParams correlationId], message);
    
    [authorityValidation validateAuthority:authority authorityHost:authorityHost completionBlock:completionBlock];
}

@end
