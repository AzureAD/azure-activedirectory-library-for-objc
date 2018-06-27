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

#import "ADEnrollmentGateway.h"
#import "NSURL+ADExtensions.h"
#import "ADAuthorityValidation.h"
#import "ADAuthenticationError+Internal.h"

// Keys for Intune Enrollment ID
#define AD_INTUNE_ENROLLMENT_ID @"intune_app_protection_enrollment_id_V"
#define AD_INTUNE_ENROLLMENT_ID_VERSION @"1"
#define AD_INTUNE_ENROLLMENT_ID_KEY (AD_INTUNE_ENROLLMENT_ID AD_INTUNE_ENROLLMENT_ID_VERSION)

// Keys for Intune Resource
#define AD_INTUNE_RESOURCE_ID @"intune_mam_resource_V"
#define AD_INTUNE_RESOURCE_ID_VERSION @"1"
#define AD_INTUNE_RESOURCE_ID_KEY (AD_INTUNE_RESOURCE_ID AD_INTUNE_RESOURCE_ID_VERSION)

NSString *const ENROLLMENT_ID_ARRAY = @"enrollment_ids";

NSString *const TID = @"tid";
NSString *const OID = @"oid";
NSString *const UNIQUE_ACCOUNT_ID = @"unique_account_id";
NSString *const USER_ID = @"user_id";
NSString *const ENROLLMENT_ID = @"enrollment_id";

static NSString *s_intuneEnrollmentIdJSON = nil;
static NSString *s_intuneResourceJSON = nil;


@interface ADEnrollmentGateway()

+ (NSString *)getEnrollmentIDForIdentifier:(BOOL (^)(NSDictionary*)) idBlock error:(ADAuthenticationError * __autoreleasing *)error;

@end

@implementation ADEnrollmentGateway

+ (NSString *)getEnrollmentIDForIdentifier:(BOOL (^)(NSDictionary*)) idBlock error:(ADAuthenticationError * __autoreleasing *)error
{
    NSString *enrollIdJSON = [ADEnrollmentGateway allEnrollmentIds];

    if (!enrollIdJSON)
    {
        AD_LOG_VERBOSE(nil,@"No Intune Enrollment ID JSON found.");
        return nil;
    }

    NSError *internalError = nil;
    id enrollIds = [NSJSONSerialization JSONObjectWithData:[enrollIdJSON dataUsingEncoding:NSUTF8StringEncoding] options:kNilOptions error:&internalError];

    if (internalError || !enrollIds)
    {
        if(error)
        {
            *error = [ADAuthenticationError errorFromNSError:internalError
                                                      errorDetails:[NSString stringWithFormat:@"Could not de-serialize Intune Enrollment ID JSON: <%@>", internalError.description]
                                                     correlationId:nil];
        }
        return nil;
    }
    else if (![enrollIds isKindOfClass:[NSDictionary class]])
    {
        if(error)
        {
            *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                            protocolCode:nil
                                                            errorDetails:@"Intune Enrollment ID JSON structure is incorrect. (Not a dictionary)"
                                                           correlationId:nil];
        }
        return nil;
    }

    enrollIds = enrollIds[ENROLLMENT_ID_ARRAY];

    if (!enrollIds || ![enrollIds isKindOfClass:[NSArray class]])
    {
        if(error)
        {
            *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                                  protocolCode:nil
                                                                  errorDetails:@"Intune Enrollment ID JSON structure is incorrect. (Not an array)"
                                                                 correlationId:nil];
        }
        return nil;
    }

    for (NSDictionary *enrollIdDic in enrollIds)
    {
        if (idBlock(enrollIdDic))
            return [enrollIdDic objectForKey:ENROLLMENT_ID];
    }

    return nil;
}

+ (NSString *)allEnrollmentIds
{
    @synchronized (self)
    {
        if (s_intuneEnrollmentIdJSON)
            return s_intuneEnrollmentIdJSON;
    }

    return [[NSUserDefaults standardUserDefaults] objectForKey:AD_INTUNE_ENROLLMENT_ID_KEY];
}

+ (NSString *)enrollmentIdForUserId:(NSString *)userId error:(ADAuthenticationError * __autoreleasing *)error
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary *dic) {
        return [[dic objectForKey:USER_ID] isEqualToString:userId];
    }
                                                       error:error];
}

+ (NSString *)enrollmentIdForUserObjectId:(NSString *)userObjectId tenantId:(NSString *)tenantId error:(ADAuthenticationError * __autoreleasing *)error
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary *dic) {
        return [[dic objectForKey:OID] isEqualToString:userObjectId] && [[dic objectForKey:TID] isEqualToString:tenantId];
    }
                                                       error:error];
}

+ (NSString *)enrollmentIdForUniqueAccountId:(NSString *)uniqueAccountId error:(ADAuthenticationError * __autoreleasing *)error
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary *dic) {
        return [[dic objectForKey:UNIQUE_ACCOUNT_ID] isEqualToString:uniqueAccountId];
    }
                                                       error:error];
}

+ (NSString *)intuneMamResource:(NSURL *)authority error:(ADAuthenticationError * __autoreleasing *)error
{
    NSString *resourceJSON = nil;

    @synchronized(self)
    {
        if (s_intuneResourceJSON)
        {
            resourceJSON = s_intuneResourceJSON;
        }
    }

    if (!resourceJSON)
    {
        resourceJSON = [[NSUserDefaults standardUserDefaults] objectForKey:AD_INTUNE_RESOURCE_ID_KEY];
        if (!resourceJSON)
        {
            AD_LOG_VERBOSE(nil,@"No Intune Resource JSON found.");
            return nil;
        }
    }
    NSError *internalError = nil;
    id resources = [NSJSONSerialization JSONObjectWithData:[resourceJSON dataUsingEncoding:NSUTF8StringEncoding] options:kNilOptions error:&internalError];

    if (internalError  || !resources)
    {
        if(error)
        {
            *error = [ADAuthenticationError errorFromNSError:internalError
                                                      errorDetails:[NSString stringWithFormat:@"Could not de-serialize Intune Resource JSON: <%@>", internalError.description]
                                                     correlationId:nil];
        }
        return nil;
    }
    else if (![resources isKindOfClass:[NSDictionary class]])
    {
        if(error)
        {
            *error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                                                  protocolCode:nil
                                                                  errorDetails:@"Intune Resource JSON structure is incorrect. (Not a dictionary)"
                                                                 correlationId:nil];
        }
        return nil;
    }

    NSArray<NSURL *> *aliases = [[ADAuthorityValidation sharedInstance] cacheAliasesForAuthority:authority];

    for(NSURL *alias in aliases)
    {
        NSString *host = [alias adHostWithPortIfNecessary];

        if(resources[host])
            return resources[host];
    }

    return nil;
}

+ (void)setIntuneMamResourceWithJsonBlob:(NSString *)resources
{
    @synchronized (self)
    {
        s_intuneResourceJSON = [resources copy];
    }
}

+ (void)setEnrollmentIdsWithJsonBlob:(NSString *)enrollmentIds
{
    @synchronized (self)
    {
        s_intuneEnrollmentIdJSON = [enrollmentIds copy];
    }
}

@end
