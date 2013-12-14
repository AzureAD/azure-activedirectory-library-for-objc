// Created by Boris Vidolov on 10/15/13.
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
#import "ADALiOS.h"
#import "ADOAuth2Constants.h"

NSString* const ID_TOKEN_SUBJECT = @"sub";
NSString* const ID_TOKEN_TENANTID = @"tid";
NSString* const ID_TOKEN_UPN = @"upn";
NSString* const ID_TOKEN_GIVEN_NAME = @"given_name";
NSString* const ID_TOKEN_FAMILY_NAME = @"family_name";
NSString* const ID_TOKEN_UNIQUE_NAME = @"unique_name";
NSString* const ID_TOKEN_EMAIL = @"email";
NSString* const ID_TOKEN_IDENTITY_PROVIDER = @"idp";

@implementation ADUserInformation

-(id) init
{
    //Throws, as this init function should not be used
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id) initWithUserId: (NSString*) userId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(userId);//Shouldn't be called with nil.
    self = [super init];
    if (self)
    {
        //Minor canonicalization of the userId:
        _userId = [userId trimmedString].lowercaseString;
    }
    return self;
}

#define RETURN_ID_TOKEN_ERROR(text) \
{ \
    ADAuthenticationError* idTokenError = [self errorFromIdToken:text]; \
    if (error) \
    { \
        *error = idTokenError; \
    } \
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
    if (![NSString isStringNilOrBlank:read]) \
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
        return nil;

    if ([NSString isStringNilOrBlank:idToken])
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    
    NSArray* parts = [idToken componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"."]];
    if (parts.count < 1)
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    
    for (NSString* part in parts)
    {
        AD_LOG_VERBOSE(@"Id_token", part);
        NSString* decoded = [part adBase64Decode];
        if (![NSString isStringNilOrBlank:decoded])
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
            
            EXTRACT_ID_TOKEN_PROPERTY(GivenName, ID_TOKEN_GIVEN_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(FamilyName, ID_TOKEN_FAMILY_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(Subject, ID_TOKEN_SUBJECT);
            EXTRACT_ID_TOKEN_PROPERTY(TenantId, ID_TOKEN_TENANTID);
            EXTRACT_ID_TOKEN_PROPERTY(Upn, ID_TOKEN_UPN);
            EXTRACT_ID_TOKEN_PROPERTY(UniqueName, ID_TOKEN_UNIQUE_NAME);
            EXTRACT_ID_TOKEN_PROPERTY(EMail, ID_TOKEN_EMAIL);
            EXTRACT_ID_TOKEN_PROPERTY(IdentityProvider, ID_TOKEN_IDENTITY_PROVIDER);
        }
    }
    
    //Now attempt to extract an unique user id:
    
    if (![NSString isStringNilOrBlank:self.uniqueName])
    {
        _userId = self.uniqueName;
        self.userIdDisplayable = true;//This is what the server provided
    }
    else if (![NSString isStringNilOrBlank:self.eMail])
    {
        _userId = self.eMail;
        self.userIdDisplayable = true;
    }
    else
    
    if (!self.userId)
    {
        RETURN_ID_TOKEN_ERROR(idToken);
    }
    
    return self;
}

+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(userId);
    ADUserInformation* userInfo = [[ADUserInformation alloc] initWithUserId:userId];
    return userInfo;
}

+(ADUserInformation*) userInformationWithIdToken: (NSString*) idToken
                                           error: (ADAuthenticationError* __autoreleasing*) error
{
    RETURN_NIL_ON_NIL_ARGUMENT(idToken);
    
    return [[ADUserInformation alloc] initWithIdToken:idToken error:error];
}

-(id) copyWithZone:(NSZone*) zone
{
    //Deep copy. Note that the user may have passed NSMutableString objects, so all of the objects should be copied:
    ADUserInformation* info = [[ADUserInformation allocWithZone:zone] initWithUserId:[self.userId copyWithZone:zone]];
    info.userIdDisplayable = self.userIdDisplayable;
    info.givenName = [self.givenName copyWithZone:zone];
    info.familyName = [self.familyName copyWithZone:zone];
    info.identityProvider = [self.identityProvider copyWithZone:zone];
    
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
}

//Deserialize:
-(id) initWithCoder:(NSCoder *) aDecoder
{
    NSString* storedUserId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"userId"];
    if ([NSString isStringNilOrBlank:storedUserId])
    {
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"Invalid userId: %@", storedUserId];
        AD_LOG_ERROR(@"Invalid user information", message, AD_ERROR_BAD_CACHE_FORMAT);
        
        return nil;
    }
    self = [self initWithUserId:storedUserId];
    if (self)
    {
        self.userIdDisplayable = [aDecoder decodeBoolForKey:@"userIdDisplayable"];
        self.givenName = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"givenName"];
        self.familyName = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"familyName"];
        self.identityProvider = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"identityProvider"];
    }
    
    return self;
}

@end
