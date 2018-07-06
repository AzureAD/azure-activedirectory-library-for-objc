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
#import "ADUserInformation+Internal.h"
#import "ADAL_Internal.h"
#import "ADHelpers.h"

//Declares a propperty getter, which extracts the property from the claims dictionary
#define ID_TOKEN_PROPERTY_GETTER(property, claimName) \
-(NSString*) property \
{ \
return [self.allClaims objectForKey:claimName]; \
}

@implementation ADUserInformation

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
    return [ADHelpers normalizeUserId:userId];
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

+ (ADUserInformation *)userInformationWithIdToken:(NSString *)idToken
                                            error:(ADAuthenticationError * __autoreleasing *)error
{
    return [[ADUserInformation alloc] initWithIdToken:idToken
                                        homeAccountId:nil
                                                error:error];
}

- (id)copyWithZone:(NSZone *)zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    NSString *idtoken = [_rawIdToken copyWithZone:zone];
    NSString *homeAccountId = [_homeAccountId copyWithZone:zone];
    ADUserInformation *info = [[ADUserInformation allocWithZone:zone] initWithIdToken:idtoken
                                                                        homeAccountId:homeAccountId
                                                                                error:nil];
    return info;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
    {
        return NO;
    }
    
    if (self == object)
    {
        return YES;
    }
    
    if (![object isKindOfClass:[ADUserInformation class]])
    {
        return NO;
    }
    
    ADUserInformation *rhs = (ADUserInformation *)object;
    
    BOOL result = YES;
    result &= (!self.rawIdToken && !rhs.rawIdToken) || [self.rawIdToken isEqualToString:rhs.rawIdToken];
    result &= (!self.homeAccountId && !rhs.homeAccountId) || [self.homeAccountId isEqualToString:rhs.homeAccountId];
    
    return result;
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
    
    return [self initWithIdToken:idToken
                   homeAccountId:nil
                           error:nil];
}

@end
