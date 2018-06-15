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

// Keys for Intune Enrollment ID
NSString* const ADIntuneAppProtectionEnrollmentID = @"intune_app_protection_enrollment_id_V";
NSString* const ADIntuneAppProtectionEnrollmentIDVersion = @"1";
#define AD_INTUNE_ENROLLMENT_ID_KEY [ADIntuneAppProtectionEnrollmentID stringByAppendingString:ADIntuneAppProtectionEnrollmentIDVersion]
NSString* const enrollmentIdArray = @"enrollment_ids";

NSString* const tid = @"tid";
NSString* const oid = @"oid";
NSString* const unique_account_id = @"unique_account_id";
NSString* const user_id = @"user_id";
NSString* const enrollment_id = @"enrollment_id";

// Keys for Intune Resource
NSString* const ADIntuneAppProtectionResourceID = @"intune_mam_resource_V";
NSString* const ADIntuneAppProtectionResourceIDVersion = @"1";
#define AD_INTUNE_RESOURCE_ID_KEY [ADIntuneAppProtectionEnrollmentID stringByAppendingString:ADIntuneAppProtectionEnrollmentIDVersion]

static NSString* ADIntuneEnrollmentIdJSON = nil;
static NSString* ADIntuneResourceJSON = nil;


@interface ADEnrollmentGateway()

+ (NSString*) getEnrollmentIDForIdentifier:(BOOL (^)(NSDictionary*)) idBlock;
+ (NSString *) normalizeAuthority:(NSString *)authority;

@end

@implementation ADEnrollmentGateway

+ (NSString*) getEnrollmentIDForIdentifier:(BOOL (^)(NSDictionary*)) idBlock
{
    NSString* enrollIdJSON = [ADEnrollmentGateway allEnrollmentIds];

    if (!enrollIdJSON)
        return nil;

    NSError* error = nil;
    id enrollIds = [NSJSONSerialization JSONObjectWithData:[enrollIdJSON dataUsingEncoding:NSUTF8StringEncoding] options:kNilOptions error:&error];

    if (error)
        return nil;

    enrollIds = enrollIds[enrollmentIdArray];

    if (!enrollIds)
        return nil;

    for (NSDictionary* enrollIdDic in enrollIds)
    {
        if (idBlock(enrollIdDic))
            return [enrollIdDic objectForKey:enrollment_id];
    }

    return nil;
}

+ (NSString *)allEnrollmentIds
{
    if (ADIntuneEnrollmentIdJSON)
        return ADIntuneEnrollmentIdJSON;

    return [[NSUserDefaults standardUserDefaults] objectForKey:AD_INTUNE_ENROLLMENT_ID_KEY];
}

+ (NSString *)allIntuneMAMResources
{
    if (ADIntuneResourceJSON)
        return ADIntuneResourceJSON;

    return [[NSUserDefaults standardUserDefaults] objectForKey:AD_INTUNE_RESOURCE_ID_KEY];
}

+ (NSString *)enrollmentIdForUserId:(NSString *)userId;
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary * dic) {
        return [[dic objectForKey:user_id] isEqualToString:userId];
    }];
}

+ (NSString *)enrollmentIdForUserObjectId:(NSString *)userObjectId tenantId:(NSString *)tenantId
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary * dic) {
        return [[dic objectForKey:oid] isEqualToString:userObjectId] && [[dic objectForKey:tid] isEqualToString:tenantId];
    }];
}

+ (NSString *)enrollmentIdForUniqueAccountId:(NSString *)uniqueAccountId
{
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary * dic) {
        return [[dic objectForKey:unique_account_id] isEqualToString:uniqueAccountId];
    }];
}

+ (NSString *)enrollmentIdIfAvailable
{
    // this will just return the first enrollment ID
    return [ADEnrollmentGateway getEnrollmentIDForIdentifier:^BOOL(NSDictionary * __unused dic) {
        return true;
    }];
}

+ (NSString*)enrollmentIDForTokenUserID:(NSString*) tokenUserID requestUserID:(NSString*) requestUserID
{
    NSString* enrollmentID;
    enrollmentID = tokenUserID ? [ADEnrollmentGateway enrollmentIdForUserId:tokenUserID] : nil;
    if (enrollmentID)
        return enrollmentID;

    enrollmentID = requestUserID ? [ADEnrollmentGateway enrollmentIdForUserId:requestUserID] : nil;
    if (enrollmentID)
        return enrollmentID;

    enrollmentID = [ADEnrollmentGateway enrollmentIdIfAvailable];
    return enrollmentID;
}

+ (NSString *) normalizeAuthority:(NSString *)authority
{
    NSURL* authorityURL = [NSURL URLWithString:authority];
    NSNumber *port = authorityURL.port;

    // This assumes we're using https, which is mandatory for all AAD communications.
    if (port == nil || port.intValue == 443)
    {
        return authorityURL.host.lowercaseString;
    }
    return [NSString stringWithFormat:@"%@:%d", authorityURL.host.lowercaseString, port.intValue];
}

+ (NSString *)intuneMamResource:(NSString *)authority
{
    NSString* resourceJSON = [ADEnrollmentGateway allIntuneMAMResources];

    if (!resourceJSON)
        return nil;

    NSError* error = nil;
    id resources = [NSJSONSerialization JSONObjectWithData:[resourceJSON dataUsingEncoding:NSUTF8StringEncoding] options:kNilOptions error:&error];

    if (error)
        return nil;

    return resources[[ADEnrollmentGateway normalizeAuthority:authority]];
}

+ (NSString *)intuneMAMResourceJSON:(NSString *)authority
{
    NSString* mamResource = [ADEnrollmentGateway intuneMamResource:authority];
    mamResource = mamResource ? [NSString stringWithFormat:@"{%@:%@}",[ADEnrollmentGateway normalizeAuthority:authority],mamResource] : nil ;

    return mamResource;
}


#if AD_BROKER
+ (void)setIntuneMamResourceWithJsonBlob:(NSString *)resources
{
    if (!resources)
        ADIntuneResourceJSON = nil;

    ADIntuneResourceJSON = [resources copy];
}

+ (void)setEnrollmentIdsWithJsonBlob:(NSString *)enrollmentIds
{
    if (!enrollmentIds)
        ADIntuneEnrollmentIdJSON = nil;

    ADIntuneEnrollmentIdJSON = [enrollmentIds copy];
}
#endif

@end
