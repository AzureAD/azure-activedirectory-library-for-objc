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

#import "ADProfileInfo.h"
#import "ADALiOS.h"
#import "ADOAuth2Constants.h"
#import "NSString+ADHelperMethods.h"

static NSString* const PROFILE_INFO_SUBJECT = @"sub";
static NSString* const PROFILE_INFO_TENANTID = @"tid";
static NSString* const PROFILE_INFO_PREFERRED_USERNAME = @"preferred_username";
static NSString* const PROFILE_INFO_FRIENDLY_NAME = @"name";
static NSString* const PROFILE_INFO_TYPE = @"typ";
static NSString* const PROFILE_INFO_JWT_TYPE = @"JWT";
static NSString* const PROFILE_INFO_VER = @"ver";

@implementation ADProfileInfo

- (id)init
{
    //Throws, as this init function should not be used
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+ (NSString*)normalizeUserId: (NSString*) userId
{
    if (!userId)
    {
        return nil;//Quick exit;
    }
    NSString* normalized = [userId adTrimmedString].lowercaseString;
        
    return normalized;
}

- (id)initWithUsername:(NSString*)username
{
    if (!username)
    {
        return nil;
    }
    
    if (!(self = [super init]))
    {
        return nil;
    }
    
    //Minor canonicalization of the userId:
    _allClaims = @{ PROFILE_INFO_PREFERRED_USERNAME : [self.class normalizeUserId:username] };
    
    return self;
}

static ADAuthenticationError* _errorFromInfo(const char* cond, NSString* profileInfo)
{
    NSString* errorDetails = nil;
    if (profileInfo)
    {
        errorDetails = [NSString stringWithFormat:@"The profile_info contents cannot be parsed, %s. (profile_info = %@)", cond, profileInfo];
    }
    else
    {
        errorDetails = @"No profile_info was received.";
    }
    
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION
                                                  protocolCode:nil
                                                  errorDetails:errorDetails];
}

#define CHECK_PROFILE_INFO_ERROR(_cond) \
{ \
    if (!_cond) { \
        ADAuthenticationError* _profileError = _errorFromInfo(#_cond, encodedString); \
        if (error) \
        { \
            *error = _profileError; \
        } \
        return nil; \
    } \
}

- (id)initWithEncodedString:(NSString*)encodedString
                    error:(ADAuthenticationError* __autoreleasing *)error
{
    CHECK_PROFILE_INFO_ERROR(encodedString);
    CHECK_PROFILE_INFO_ERROR((![NSString adIsStringNilOrBlank:encodedString]));
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _rawProfileInfo = encodedString;
    NSMutableDictionary* allClaims = [NSMutableDictionary new];
    
    NSArray* parts = [encodedString componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"."]];
    CHECK_PROFILE_INFO_ERROR(parts.count > 0);
    
    NSString* type = nil;
    for (int i = 0; i < parts.count; i++)
    {
        NSString* decoded = [parts[i] adBase64UrlDecode];
        CHECK_PROFILE_INFO_ERROR(![NSString adIsStringNilOrBlank:decoded]);
        
        NSError* jsonError  = nil;
        id jsonObject = [NSJSONSerialization JSONObjectWithData:[decoded dataUsingEncoding:NSUTF8StringEncoding]
                                                        options:0
                                                          error:&jsonError];
        if (jsonError)
        {
            ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:jsonError
                                                                        errorDetails:[NSString stringWithFormat:@"Failed to deserialize the profile_info contents: %@", parts[i]]];
            if (error)
            {
                *error = adError;
            }
            return nil;
        }
        
        CHECK_PROFILE_INFO_ERROR([jsonObject isKindOfClass:[NSDictionary class]]);
        
        NSDictionary* contents = (NSDictionary*)jsonObject;
        if (!type)
        {
            type = [contents objectForKey:PROFILE_INFO_TYPE];
            if (type)
            {
                //Type argument is passed, check if it is the expected one
                if (![PROFILE_INFO_JWT_TYPE isEqualToString:type])
                {
                    //Log it, but still try to use it as if it was a JWT token
                    AD_LOG_WARN(@"Incompatible id_token type.", type);
                }
            }
        }

        [allClaims addEntriesFromDictionary:contents];
    }
    if (!type)
    {
        AD_LOG_WARN(@"The id_token type is missing.", @"Assuming JWT type.");
    }
    
    //Create a read-only dictionary object. Note that the properties checked below are calculated off this dictionary:
    _allClaims = [NSDictionary dictionaryWithDictionary:allClaims];

    return self;
}

//Declares a propperty getter, which extracts the property from the claims dictionary
#define PROFILE_INFO_PROPERTY_GETTER(property, claimName) \
- (NSString*)property \
{ \
    return [[self allClaims] objectForKey:claimName]; \
}

PROFILE_INFO_PROPERTY_GETTER(subject, PROFILE_INFO_SUBJECT);
PROFILE_INFO_PROPERTY_GETTER(tenantId, PROFILE_INFO_TENANTID);
PROFILE_INFO_PROPERTY_GETTER(friendlyName, PROFILE_INFO_FRIENDLY_NAME);
PROFILE_INFO_PROPERTY_GETTER(version, PROFILE_INFO_VER);
PROFILE_INFO_PROPERTY_GETTER(username, PROFILE_INFO_PREFERRED_USERNAME);

+ (ADProfileInfo*)profileInfoWithUsername:(NSString*)username
                                    error:(ADAuthenticationError* __autoreleasing*)error
{
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(username);
    return [[ADProfileInfo alloc] initWithUsername:username];
}

+ (ADProfileInfo*)profileInfoWithEncodedString:(NSString*)encodedString
                                         error:(ADAuthenticationError* __autoreleasing*)error
{
    RETURN_NIL_ON_NIL_ARGUMENT(encodedString);
    
    return [[ADProfileInfo alloc] initWithEncodedString:encodedString
                                                  error:error];
}

- (id)copyWithZone:(NSZone*)zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    
    // If we still have the raw encoded string just pass that along for the copy
    if (self.rawProfileInfo)
    {
        return [[ADProfileInfo allocWithZone:zone] initWithEncodedString:self.rawProfileInfo error:nil];
    }
    
    // Otherwise we're stuck copying things field by field
    
    ADProfileInfo* info = [[ADProfileInfo allocWithZone:zone] initWithUsername:self.username];
    if (!info)
    {
        return nil;
    }
    
    info->_allClaims = [self.allClaims copyWithZone:zone];
    
    return info;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

//Serialize:
- (void)encodeWithCoder:(NSCoder *)aCoder
{
    // If we have the raw profile info just encode that
    [aCoder encodeObject:_rawProfileInfo forKey:@"rawProfileInfo"];
    
    // If we don't have it that means this is a mocked up object. Just encode
    // allClaims then
    if (!_rawProfileInfo)
    {
        [aCoder encodeObject:_allClaims forKey:@"allClaims"];
    }
}

//Deserialize:
- (id)initWithCoder:(NSCoder *)aDecoder
{
    NSString* storedRawInfo = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"rawProfileInfo"];
    if (storedRawInfo)
    {
        return [self initWithEncodedString:storedRawInfo error:nil];
    }
    
    _allClaims = [aDecoder decodeObjectOfClass:[NSDictionary class] forKey:@"allClaims"];
    
    return self;
}

- (BOOL)isEqual:(id)object
{
    if (![object isKindOfClass:[ADProfileInfo class]])
    {
        return NO;
    }
    
    ADProfileInfo* other = (ADProfileInfo*)object;
    return [_allClaims isEqualToDictionary:other->_allClaims];
}

@end
