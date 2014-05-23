// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADUserInformation.h"
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

@synthesize eMail             = _eMail;
@synthesize familyName        = _familyName;
@synthesize givenName         = _givenName;
@synthesize guestId           = _guestId;
@synthesize identityProvider  = _identityProvider;
@synthesize subject           = _subject;
@synthesize tenantId          = _tenantId;
@synthesize uniqueName        = _uniqueName;
@synthesize upn               = _upn;
@synthesize userId            = _userId;
@synthesize userIdDisplayable = _userIdDisplayable;
@synthesize userObjectId      = _userObjectId;

- (void)dealloc
{
    AD_LOG_VERBOSE(@"ADUserInformation", @"dealloc");
    
    SAFE_ARC_RELEASE(_eMail);
    SAFE_ARC_RELEASE(_familyName);
    SAFE_ARC_RELEASE(_givenName);
    SAFE_ARC_RELEASE(_guestId);
    SAFE_ARC_RELEASE(_identityProvider);
    SAFE_ARC_RELEASE(_subject);
    SAFE_ARC_RELEASE(_tenantId);
    SAFE_ARC_RELEASE(_uniqueName);
    SAFE_ARC_RELEASE(_upn);
    SAFE_ARC_RELEASE(_userId);
    SAFE_ARC_RELEASE(_userObjectId);
    
    SAFE_ARC_SUPER_DEALLOC();
}

-(id) init
{
    //Throws, as this init function should not be used
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+(NSString*) normalizeUserId: (NSString*) userId
{
    if (!userId)
    {
        return nil;//Quick exit;
    }
    NSString* normalized = [userId adTrimmedString].lowercaseString;
        
    return normalized.length ? normalized : nil;
}

-(id) initWithUserId: (NSString*) userId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(userId);//Shouldn't be called with nil.
    self = [super init];
    if (self)
    {
        //Minor canonicalization of the userId:
        _userId = SAFE_ARC_RETAIN( [self.class normalizeUserId:userId] );
    }
    return self;
}

//IMPORTANT: this macro should be used only in the initializer, as it releases "self"
//in case of error
#define RETURN_ID_TOKEN_ERROR(text) \
{ \
    ADAuthenticationError* idTokenError = [self errorFromIdToken:text]; \
    if (error) \
    { \
        *error = idTokenError; \
    } \
    SAFE_ARC_AUTORELEASE(self); \
    return nil; \
}


-(ADAuthenticationError*) errorFromIdToken: (NSString*) idTokenText
{
    THROW_ON_NIL_ARGUMENT(idTokenText);
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION protocolCode:nil errorDetails:[NSString stringWithFormat: @"The id_token contents cannot be parsed: %@", idTokenText]];
}

#define EXTRACT_ID_TOKEN_PROPERTY(property, name) \
{ \
    NSString* read = [contents objectForKey:name]; \
    if (![NSString adIsStringNilOrBlank:read]) \
    { \
        [self set##property:read]; \
    } \
}

-(id) initWithIdToken: (NSString*) idToken
                error: (ADAuthenticationError* __autoreleasing*) error
{
    THROW_ON_NIL_ARGUMENT(idToken);
    self = [super init];
    if (!self)
    {
        return nil;
    }

    if ([NSString adIsStringNilOrBlank:idToken])
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    
    NSArray* parts = [idToken componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"."]];
    if (parts.count < 1)
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    
    NSString* type = nil;
    for (NSString* part in parts)
    {
        AD_LOG_VERBOSE(@"Id_token part", part);
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
                                                                                errorDetails:[NSString stringWithFormat:@"Failed to deserialize the id_token contents: %@", part]];
                    if (error)
                    {
                        *error = adError;
                    }
                    return nil;
                }
            
            if (![jsonObject isKindOfClass:[NSDictionary class]])
            {
                RETURN_ID_TOKEN_ERROR(part);
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
                        AD_LOG_WARN(@"Incompatible id_token type.", type);
                    }
                }
            }
            EXTRACT_ID_TOKEN_PROPERTY(GivenName, ID_TOKEN_GIVEN_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(FamilyName, ID_TOKEN_FAMILY_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(Subject, ID_TOKEN_SUBJECT);
            EXTRACT_ID_TOKEN_PROPERTY(TenantId, ID_TOKEN_TENANTID);
            EXTRACT_ID_TOKEN_PROPERTY(Upn, ID_TOKEN_UPN);
            EXTRACT_ID_TOKEN_PROPERTY(UniqueName, ID_TOKEN_UNIQUE_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(EMail, ID_TOKEN_EMAIL);
            EXTRACT_ID_TOKEN_PROPERTY(IdentityProvider, ID_TOKEN_IDENTITY_PROVIDER);
            EXTRACT_ID_TOKEN_PROPERTY(UserObjectId, ID_TOKEN_OBJECT_ID);
            EXTRACT_ID_TOKEN_PROPERTY(GuestId, ID_TOKEN_GUEST_ID);
        }
    }
    if (!type)
    {
        AD_LOG_WARN(@"The id_token type is missing.", @"Assuming JWT type.");
    }
    
    //Now attempt to extract an unique user id:
    if (![NSString adIsStringNilOrBlank:self.upn])
    {
        _userId = self.upn;
        self.userIdDisplayable = YES;
    }
    else if (![NSString adIsStringNilOrBlank:self.eMail])
    {
        _userId = self.eMail;
        self.userIdDisplayable = YES;
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
        self.userIdDisplayable = YES;//This is what the server provided
    }
    else if (![NSString adIsStringNilOrBlank:self.guestId])
    {
        _userId = self.guestId;
    }
    else
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    _userId = SAFE_ARC_RETAIN( [self.class normalizeUserId:_userId] );
    
    return self;
}

+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(userId);

    return SAFE_ARC_AUTORELEASE([[ADUserInformation alloc] initWithUserId:userId]);
}

+(ADUserInformation*) userInformationWithIdToken: (NSString*) idToken
                                           error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_NIL_ON_NIL_ARGUMENT(idToken);
    
    return SAFE_ARC_AUTORELEASE( [[ADUserInformation alloc] initWithIdToken:idToken error:error] );
}

-(id) copyWithZone:(NSZone*) zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    ADUserInformation* info = [[ADUserInformation allocWithZone:zone] initWithUserId:SAFE_ARC_AUTORELEASE([self.userId copyWithZone:zone])];
    
    info->_userIdDisplayable  = self.userIdDisplayable;
    info->_givenName          = [self.givenName copyWithZone:zone];
    info->_familyName         = [self.familyName copyWithZone:zone];
    info->_identityProvider   = [self.identityProvider copyWithZone:zone];
    info->_tenantId           = [self.tenantId copyWithZone:zone];
    info->_eMail              = [self.eMail copyWithZone:zone];
    info->_uniqueName         = [self.uniqueName copyWithZone:zone];
    info->_upn                = [self.upn copyWithZone:zone];
    info->_subject            = [self.subject copyWithZone:zone];
    info->_userObjectId       = [self.userObjectId copyWithZone:zone];
    info->_guestId            = [self.guestId copyWithZone:zone];
    
    return info;
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

//Serialize:
-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.userId forKey:@"userId"];
    [aCoder encodeBool:self.userIdDisplayable forKey:@"userIdDisplayable"];
    [aCoder encodeObject:self.givenName forKey:@"givenName"];
    [aCoder encodeObject:self.familyName forKey:@"familyName"];
    [aCoder encodeObject:self.identityProvider forKey:@"identityProvider"];
    [aCoder encodeObject:self.tenantId forKey:@"tenantId"];
    [aCoder encodeObject:self.eMail forKey:@"eMail"];
    [aCoder encodeObject:self.uniqueName forKey:@"uniqueName"];
    [aCoder encodeObject:self.upn forKey:@"upn"];
    [aCoder encodeObject:self.subject forKey:@"subject"];
    [aCoder encodeObject:self.userObjectId forKey:@"userObjectId"];
    [aCoder encodeObject:self.guestId forKey:@"guestId"];
}

//Deserialize:
-(id) initWithCoder:(NSCoder *) aDecoder
{
    NSString* storedUserId      = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"userId"];
    if ([NSString adIsStringNilOrBlank:storedUserId])
    {
        //The userId should be valid:
        AD_LOG_ERROR_F(@"Invalid user information", AD_ERROR_BAD_CACHE_FORMAT, @"Invalid userId: %@", storedUserId);
        
        return nil;
    }
    self = [self initWithUserId:storedUserId];
    if (self)
    {
        self.userIdDisplayable  = [aDecoder decodeBoolForKey:@"userIdDisplayable"];
        self.givenName          = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"givenName"];
        self.familyName         = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"familyName"];
        self.identityProvider   = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"identityProvider"];
        self.tenantId           = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"tenantId"];
        self.eMail              = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"eMail"];
        self.uniqueName         = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"uniqueName"];
        self.upn                = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"upn"];
        self.subject            = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"subject"];
        self.userObjectId       = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"userObjectId"];
        self.guestId            = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"guestId"];
    }
    
    return self;
}

@end
