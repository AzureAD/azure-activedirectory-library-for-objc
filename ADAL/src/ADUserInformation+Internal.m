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
                                      homeUserId:(NSString *)homeUserId
                                           error:(ADAuthenticationError * __autoreleasing *)error
{
    ADUserInformation *userInfo = [[ADUserInformation alloc] initWithIdToken:idToken
                                                                  homeUserId:homeUserId
                                                                       error:error];
    return userInfo;
}

- (id)initWithIdToken:(NSString *)idToken
           homeUserId:(NSString *)homeUserId
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
    _homeUserId = homeUserId;
    
    NSArray* parts = [idToken componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"."]];
    if (parts.count < 1)
    {
        RETURN_ID_TOKEN_ERROR;
    }
    
    NSMutableDictionary* allClaims = [NSMutableDictionary new];
    NSString* type = nil;
    for (NSString* part in parts)
    {
        NSString* decoded = [part msidBase64UrlDecode];
        if (![NSString msidIsStringNilOrBlank:decoded])
        {
            NSError* jsonError  = nil;
            id jsonObject = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding]
                                                            options:0
                                                              error:&jsonError];
            if (jsonError)
            {
                
                
                ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:jsonError
                                                                            errorDetails:[NSString stringWithFormat:@"Failed to deserialize the id_token contents: %@", part]
                                                                           correlationId:nil];
                if (error)
                {
                    *error = adError;
                }
                return nil;
            }
            
            if (![jsonObject isKindOfClass:[NSDictionary class]])
            {
                RETURN_ID_TOKEN_ERROR;
            }
            
            NSDictionary* contents = (NSDictionary*)jsonObject;
            if (!type)
            {
                type = [contents objectForKey:ID_TOKEN_TYPE];
                if (type)
                {
                    //Type argument is passed, check if it is the expected one
                    if (![ID_TOKEN_JWT_TYPE isEqualToString:type])
                    {
                        //Log it, but still try to use it as if it was a JWT token
                        MSID_LOG_WARN(nil, @"Incompatible id_token type - %@", type);
                    }
                }
            }

            [allClaims addEntriesFromDictionary:contents];
        }
    }
    if (!type)
    {
        MSID_LOG_WARN(nil, @"The id_token type is missing. Assuming JWT type.");
    }
    
    _allClaims = allClaims;
    
    //Now attempt to extract an unique user id:
    if (![NSString msidIsStringNilOrBlank:self.upn])
    {
        _userId = self.upn;
        _userIdDisplayable = YES;
    }
    else if (![NSString msidIsStringNilOrBlank:self.eMail])
    {
        _userId = self.eMail;
        _userIdDisplayable = YES;
    }
    else if (![NSString msidIsStringNilOrBlank:self.subject])
    {
        _userId = self.subject;
    }
    else if (![NSString msidIsStringNilOrBlank:self.userObjectId])
    {
        _userId = self.userObjectId;
    }
    else if (![NSString msidIsStringNilOrBlank:self.uniqueName])
    {
        _userId = self.uniqueName;
        _userIdDisplayable = YES;//This is what the server provided
    }
    else if (![NSString msidIsStringNilOrBlank:self.guestId])
    {
        _userId = self.guestId;
    }
    else
    {
        RETURN_ID_TOKEN_ERROR;
    }
    _userId = [self.class normalizeUserId:_userId];
    
    if (![NSString msidIsStringNilOrBlank:self.userObjectId])
    {
        _uniqueId = self.userObjectId;
    }
    else if (![NSString msidIsStringNilOrBlank:self.subject])
    {
        _uniqueId = self.subject;
    }
    _uniqueId = [self.class normalizeUserId:_uniqueId];
    
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
