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

#import "ADUserInformation+Internal.h"
#import "MSIDAADIdTokenClaimsFactory.h"
#import "MSIDIdTokenClaims.h"

#define RETURN_ID_TOKEN_ERROR \
{ \
ADAuthenticationError* idTokenError = [ADUserInformation invalidIdTokenError]; \
if (error) \
{ \
*error = idTokenError; \
} \
return nil; \
}

NSString *const ID_TOKEN_SUBJECT = @"sub";
NSString *const ID_TOKEN_TENANTID = @"tid";
NSString *const ID_TOKEN_UPN = @"upn";
NSString *const ID_TOKEN_GIVEN_NAME = @"given_name";
NSString *const ID_TOKEN_FAMILY_NAME = @"family_name";
NSString *const ID_TOKEN_UNIQUE_NAME = @"unique_name";
NSString *const ID_TOKEN_EMAIL = @"email";
NSString *const ID_TOKEN_IDENTITY_PROVIDER = @"idp";
NSString *const ID_TOKEN_TYPE = @"typ";
NSString *const ID_TOKEN_JWT_TYPE = @"JWT";
NSString *const ID_TOKEN_OBJECT_ID = @"oid";
NSString *const ID_TOKEN_GUEST_ID = @"altsecid";

@implementation ADUserInformation (Internal)

+ (ADUserInformation *)userInformationWithIdToken:(NSString *)idToken
                                    homeAccountId:(NSString *)homeAccountId
                                           error:(ADAuthenticationError * __autoreleasing *)error
{
    ADUserInformation *userInfo = [[ADUserInformation alloc] initWithIdToken:idToken
                                                               homeAccountId:homeAccountId
                                                                       error:error];
    return userInfo;
}

- (id)initWithIdToken:(NSString *)idToken
        homeAccountId:(NSString *)homeAccountId
                error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    RETURN_NIL_ON_NIL_ARGUMENT(idToken);
    
    if ([NSString msidIsStringNilOrBlank:idToken])
    {
        RETURN_ID_TOKEN_ERROR;
    }
    
    _rawIdToken = idToken;
    _homeAccountId = homeAccountId;

    NSError *idTokenError = nil;
    MSIDIdTokenClaims *idTokenClaims = [MSIDAADIdTokenClaimsFactory claimsFromRawIdToken:_rawIdToken error:&idTokenError];

    if (!idTokenClaims)
    {
        if (idTokenError && error)
        {
            *error = [ADAuthenticationError errorFromNSError:idTokenError errorDetails:@"The id_token contents cannot be parsed" correlationId:nil];
        }
        else if (error)
        {
            *error = [ADUserInformation invalidIdTokenError];
        }

        return nil;
    }

    _userId = idTokenClaims.userId;
    _userIdDisplayable = idTokenClaims.userIdDisplayable;
    _uniqueId = idTokenClaims.uniqueId;
    _allClaims = [idTokenClaims jsonDictionary];

    if (!_userId)
    {
        MSID_LOG_WARN(nil, @"No user ID found in the id_token");

        if (error)
        {
            *error = [ADUserInformation invalidIdTokenError];
        }

        return nil;
    }
    
    return self;
}

+ (ADAuthenticationError *)invalidIdTokenError
{
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_INVALID_ID_TOKEN
                                                  protocolCode:nil
                                                  errorDetails:@"The id_token contents cannot be parsed."
                                                 correlationId:nil];
}

@end
