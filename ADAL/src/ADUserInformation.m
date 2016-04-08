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

#import "ADUserInformation.h"
#import "ADAL_Internal.h"
#import "ADOAuth2Constants.h"
#import "NSString+ADHelperMethods.h"

NSString* const ID_TOKEN_SUBJECT = @"sub";
NSString* const ID_TOKEN_TENANTID = @"tid";
NSString* const ID_TOKEN_UPN = @"upn";
NSString* const ID_TOKEN_GIVEN_NAME = @"given_name";
NSString* const ID_TOKEN_FAMILY_NAME = @"family_name";
NSString* const ID_TOKEN_UNIQUE_NAME = @"unique_name";
NSString* const ID_TOKEN_EMAIL = @"email";
NSString* const ID_TOKEN_IDENTITY_PROVIDER = @"idp";
NSString* const ID_TOKEN_TYPE = @"typ";
NSString* const ID_TOKEN_JWT_TYPE = @"JWT";
NSString* const ID_TOKEN_OBJECT_ID = @"oid";
NSString* const ID_TOKEN_GUEST_ID = @"altsecid";

@implementation ADUserInformation

@synthesize userId = _userId;
@synthesize rawIdToken = _rawIdToken;
@synthesize userIdDisplayable = _userIdDisplayable;
@synthesize uniqueId = _uniqueId;
@synthesize allClaims = _allClaims;

- (id)init
{
    //Throws, as this init function should not be used
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+ (NSString*)normalizeUserId:(NSString*)userId
{
    if (!userId)
    {
        return nil;//Quick exit;
    }
    NSString* normalized = [userId adTrimmedString].lowercaseString;
        
    return normalized.length ? normalized : nil;
}

- (id)initWithUserId:(NSString*)userId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(userId);//Shouldn't be called with nil.
    self = [super init];
    if (self)
    {
        //Minor canonicalization of the userId:
        _userId = [self.class normalizeUserId:userId];
    }
    return self;
}

#define RETURN_ID_TOKEN_ERROR \
{ \
    ADAuthenticationError* idTokenError = [ADUserInformation invalidIdTokenError]; \
    if (error) \
    { \
        *error = idTokenError; \
    } \
    SAFE_ARC_RELEASE(self); \
    return nil; \
}


+ (ADAuthenticationError*)invalidIdTokenError
{
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_INVALID_ID_TOKEN
                                                  protocolCode:nil
                                                  errorDetails:@"The id_token contents cannot be parsed."
                                                 correlationId:nil];
}

- (id)initWithIdToken:(NSString *)idToken
                error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!idToken)
    {
        SAFE_ARC_RELEASE(self);
        return nil;
    }

    if ([NSString adIsStringNilOrBlank:idToken])
    {
        RETURN_ID_TOKEN_ERROR;
    }
    
    _rawIdToken = idToken;
    SAFE_ARC_RETAIN(_rawIdToken);
    
    NSArray* parts = [idToken componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"."]];
    if (parts.count < 1)
    {
        RETURN_ID_TOKEN_ERROR;
    }
    
    NSMutableDictionary* allClaims = [NSMutableDictionary new];
    SAFE_ARC_AUTORELEASE(allClaims);
    NSString* type = nil;
    for (NSString* part in parts)
    {
        NSString* decoded = [part adBase64UrlDecode];
        if (![NSString adIsStringNilOrBlank:decoded])
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
                        AD_LOG_WARN(@"Incompatible id_token type.", nil, type);
                    }
                }
            }

            [allClaims addEntriesFromDictionary:contents];
        }
    }
    if (!type)
    {
        AD_LOG_WARN(@"The id_token type is missing.", nil, @"Assuming JWT type.");
    }
    
    _allClaims = allClaims;
    SAFE_ARC_RETAIN(_allClaims);
    
    //Now attempt to extract an unique user id:
    if (![NSString adIsStringNilOrBlank:self.upn])
    {
        _userId = self.upn;
        _userIdDisplayable = YES;
    }
    else if (![NSString adIsStringNilOrBlank:self.eMail])
    {
        _userId = self.eMail;
        _userIdDisplayable = YES;
    }
    else if (![NSString adIsStringNilOrBlank:self.subject])
    {
        _userId = self.subject;
    }
    else if (![NSString adIsStringNilOrBlank:self.userObjectId])
    {
        _userId = self.userObjectId;
    }
    else if (![NSString adIsStringNilOrBlank:self.uniqueName])
    {
        _userId = self.uniqueName;
        _userIdDisplayable = YES;//This is what the server provided
    }
    else if (![NSString adIsStringNilOrBlank:self.guestId])
    {
        _userId = self.guestId;
    }
    else
    {
        RETURN_ID_TOKEN_ERROR;
    }
    _userId = [self.class normalizeUserId:_userId];
    SAFE_ARC_RETAIN(_userId);
    
    if (![NSString adIsStringNilOrBlank:self.userObjectId])
    {
        _uniqueId = self.userObjectId;
    }
    else if (![NSString adIsStringNilOrBlank:self.subject])
    {
        _uniqueId = self.subject;
    }
    _uniqueId = [ADUserInformation normalizeUserId:_uniqueId];
    SAFE_ARC_RETAIN(_uniqueId);
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_userId);
    _userId = nil;
    SAFE_ARC_RELEASE(_uniqueId);
    _uniqueId = nil;
    SAFE_ARC_RELEASE(_allClaims);
    _allClaims = nil;
    SAFE_ARC_RELEASE(_rawIdToken);
    _rawIdToken = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

//Declares a propperty getter, which extracts the property from the claims dictionary
#define ID_TOKEN_PROPERTY_GETTER(property, claimName) \
-(NSString*) property \
{ \
    return [self.allClaims objectForKey:claimName]; \
}

ID_TOKEN_PROPERTY_GETTER(givenName, ID_TOKEN_GIVEN_NAME);
ID_TOKEN_PROPERTY_GETTER(familyName, ID_TOKEN_FAMILY_NAME);
ID_TOKEN_PROPERTY_GETTER(subject, ID_TOKEN_SUBJECT);
ID_TOKEN_PROPERTY_GETTER(tenantId, ID_TOKEN_TENANTID);
ID_TOKEN_PROPERTY_GETTER(upn, ID_TOKEN_UPN);
ID_TOKEN_PROPERTY_GETTER(uniqueName, ID_TOKEN_UNIQUE_NAME);
ID_TOKEN_PROPERTY_GETTER(eMail, ID_TOKEN_EMAIL);
ID_TOKEN_PROPERTY_GETTER(identityProvider, ID_TOKEN_IDENTITY_PROVIDER);
ID_TOKEN_PROPERTY_GETTER(userObjectId, ID_TOKEN_OBJECT_ID);
ID_TOKEN_PROPERTY_GETTER(guestId, ID_TOKEN_GUEST_ID);

+ (ADUserInformation*)userInformationWithIdToken:(NSString *)idToken
                                           error:(ADAuthenticationError * __autoreleasing *)error
{
    RETURN_NIL_ON_NIL_ARGUMENT(idToken);
    ADUserInformation* userInfo = [[ADUserInformation alloc] initWithIdToken:idToken error:error];
    SAFE_ARC_AUTORELEASE(userInfo);
    return userInfo;
}

- (id)copyWithZone:(NSZone *)zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    NSString* idtoken = [_rawIdToken copyWithZone:zone];
    ADUserInformation* info = [[ADUserInformation allocWithZone:zone] initWithIdToken:idtoken
                                                                                error:nil];
    SAFE_ARC_RELEASE(idtoken);
    return info;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

// Serialize:
- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:_rawIdToken forKey:@"rawIdToken"];
    
    // There was no official support for Mac in ADAL 1.x, so no need for this back compat code
    // which would greatly increase the size of the user information blobs.
#if TARGET_OS_IPHONE
    // These are needed for back-compat with ADAL 1.x
    [aCoder encodeObject:_allClaims forKey:@"allClaims"];
    [aCoder encodeObject:_userId forKey:@"userId"];
    [aCoder encodeBool:_userIdDisplayable forKey:@"userIdDisplayable"];
#endif
}

// Deserialize:
- (id)initWithCoder:(NSCoder *)aDecoder
{
    NSString* idToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"rawIdToken"];
    
    return [self initWithIdToken:idToken error:nil];
}

@end
