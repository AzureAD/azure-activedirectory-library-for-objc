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

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import "ADEnrollmentGateway.h"
#import "ADEnrollmentGateway+TestUtil.h"

@interface ADEnrollmentGateway ()

+ (void)setEnrollmentIdsWithJsonBlob:(NSString *)enrollmentIds;
+ (void)setIntuneMAMResourceWithJsonBlob:(NSString *)resources;

@end

@interface ADEnrollmentGatewayTests : ADTestCase
@end

@implementation ADEnrollmentGatewayTests

- (void)setUp
{
    [super setUp];

    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADEnrollmentGateway getTestEnrollmentIDJSON]];

    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADEnrollmentGateway getTestResourceJSON]];
}

- (void)tearDown
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:@"{}"];

    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:@"{}"];
    
    [super tearDown];
}

- (void)testenrollmentIdForUserId_whenJSONIsCorrect_shouldReturnEnrollmentID
{
    ADAuthenticationError *error = nil;
    XCTAssert([@"adf79e3f-mike-454d-9f0f-2299e76dbfd5" isEqualToString:[ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]]);
    XCTAssertNil(error);

    XCTAssert([@"64d0557f-dave-4193-b630-8491ffd3b180" isEqualToString:[ADEnrollmentGateway enrollmentIdForUserId:@"dave@contoso.com" error:&error]]);
    XCTAssertNil(error);

}

- (void)testenrollmentIdForUserObjectIdtenantId_whenJSONIsCorrect_shouldReturnEnrollmentID
{
    ADAuthenticationError *error = nil;

    XCTAssert([@"adf79e3f-mike-454d-9f0f-2299e76dbfd5" isEqualToString: [ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]]);
    XCTAssertNil(error);

    XCTAssert([@"64d0557f-dave-4193-b630-8491ffd3b180" isEqualToString: [ADEnrollmentGateway enrollmentIdForUserObjectId:@"6eec576f-dave-416a-9c4a-536b178a194a" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]]);
    XCTAssertNil(error);

}

- (void)testenrollmentIdForHomeAccountId_whenJSONIsCorrect_shouldReturnEnrollmentID
{
    ADAuthenticationError *error = nil;

    XCTAssert([@"adf79e3f-mike-454d-9f0f-2299e76dbfd5" isEqualToString: [ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]]);
    XCTAssertNil(error);

    XCTAssert([@"64d0557f-dave-4193-b630-8491ffd3b180" isEqualToString: [ADEnrollmentGateway enrollmentIdForHomeAccountId:@"1e4dd613-dave-4527-b50a-97aca38b57ba" error:&error]]);
    XCTAssertNil(error);

}

- (void)testEnrollmentIDforUserId_whenJSONIsCorrupted_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"jlbasdivuhaefv98yqewrgiuyrviuahiuahiuvargiuho"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDforUserObjectId_whenJSONIsCorrupted_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"jlbasdivuhaefv98yqewrgiuyrviuahiuahiuvargiuho"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDforHomeAccountId_whenJSONIsCorrupted_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"jlbasdivuhaefv98yqewrgiuyrviuahiuahiuvargiuho"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserId_whenJSONIsEmptyString_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@""]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserObjectId_whenJSONIsEmptyString_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@""]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNotNil(error);

}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsEmptyString_shouldReturnNilAndPopulateError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@""]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNotNil(error);

}

- (void)testEnrollmentIDForUserId_whenJSONIsEmptyDictionary_shouldReturnNilWithoutError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForUserObjectId_whenJSONIsEmptyDictionary_shouldReturnNilWithoutError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNil(error);

}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsEmptyDictionary_shouldReturnNilWithoutError
{
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNil(error);

}

- (void)testEnrollmentIDForUserId_whenJSONIsArbitraryDictionary_shouldReturnNilAndPopulateError
{
    // random dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"aKey\":\"aValue\"}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserObjectId_whenJSONIsArbitraryDictionary_shouldReturnNilAndPopulateError
{
    // random dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"aKey\":\"aValue\"}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNotNil(error);

}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsArbitraryDictionary_shouldReturnNilAndPopulateError
{
    // random dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"aKey\":\"aValue\"}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserId_whenJSONIsRightHighLevelFormWithMisconfiguredEntries_shouldReturnNilWithoutError
{
    // dictionary with right form but wrong entries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[{\"aKey\":\"aValue\"},{\"anotherKey\":\"anotherValue\"}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForObjectId_whenJSONIsRightHighLevelFormWithMisconfiguredEntries_shouldReturnNilWithoutError
{
    // dictionary with right form but wrong entries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[{\"aKey\":\"aValue\"},{\"anotherKey\":\"anotherValue\"}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsRightHighLevelFormWithMisconfiguredEntries_shouldReturnNilWithoutError
{
    // dictionary with right form but wrong entries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":[{\"aKey\":\"aValue\"},{\"anotherKey\":\"anotherValue\"}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForUserId_whenJSONIsDictionaryOfDictionaries_shouldReturnNilAndPopulateError
{
    // dictionary of dictionaries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":{\"enrollment_ids\":{\"enrollment_ids\":\"enrollment_ids\"}}}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserObjectId_whenJSONIsDictionaryOfDictionaries_shouldReturnNilAndPopulateError
{
    // dictionary of dictionaries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":{\"enrollment_ids\":{\"enrollment_ids\":\"enrollment_ids\"}}}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsDictionaryOfDictionaries_shouldReturnNilAndPopulateError
{
    // dictionary of dictionaries
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"{\"enrollment_ids\":{\"enrollment_ids\":{\"enrollment_ids\":\"enrollment_ids\"}}}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNotNil(error);

}

- (void)testEnrollmentIDForUserId_whenJSONIsArrayInsteadOfDictionary_shouldReturnNilAndPopulateError
{
    // top level is array instead of dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"[{\"user_id\":\"mike@contoso.com\"},{\"home_account_id\":\"60406d5d-mike-41e1-aa70-e97501076a22\"}]"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserObjectId_whenJSONIsArrayInsteadOfDictionary_shouldReturnNilAndPopulateError
{
    // top level is array instead of dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"[{\"user_id\":\"mike@contoso.com\"},{\"home_account_id\":\"60406d5d-mike-41e1-aa70-e97501076a22\"}]"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForHomeAccountId_whenJSONIsArrayInsteadOfDictionary_shouldReturnNilAndPopulateError
{
    // top level is array instead of dictionary
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:@"[{\"user_id\":\"mike@contoso.com\"},{\"home_account_id\":\"60406d5d-mike-41e1-aa70-e97501076a22\"}]"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNotNil(error);
}

- (void)testEnrollmentIDForUserId_whenEnrollmentIdIsMissing_shouldReturnNilWithoutError
{
    // enrollmentId missing
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:
                                                       @"{\"enrollment_ids\": [\n"
                                                       "{\n"
                                                       "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n"
                                                       "\"oid\" : \"d3444455-mike-4271-b6ea-e499cc0cab46\",\n"
                                                       "\"home_account_id\" : \"60406d5d-mike-41e1-aa70-e97501076a22\",\n"
                                                       "\"user_id\" : \"mike@contoso.com\"\n"
                                                       "}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserId:@"mike@contoso.com" error:&error]);
    XCTAssertNil(error);

}

- (void)testEnrollmentIDForUserObjectId_whenEnrollmentIdIsMissing_shouldReturnNilWithoutError
{
    // enrollmentId missing
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:
                                                       @"{\"enrollment_ids\": [\n"
                                                       "{\n"
                                                       "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n"
                                                       "\"oid\" : \"d3444455-mike-4271-b6ea-e499cc0cab46\",\n"
                                                       "\"home_account_id\" : \"60406d5d-mike-41e1-aa70-e97501076a22\",\n"
                                                       "\"user_id\" : \"mike@contoso.com\"\n"
                                                       "}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForUserObjectId:@"d3444455-mike-4271-b6ea-e499cc0cab46" tenantId:@"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1" error:&error]);
    XCTAssertNil(error);

}

- (void)testEnrollmentIDForHomeAccountId_whenEnrollmentIdIsMissing_shouldReturnNilWithoutError
{
    // enrollmentId missing
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[NSString stringWithFormat:
                                                       @"{\"enrollment_ids\": [\n"
                                                       "{\n"
                                                       "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n"
                                                       "\"oid\" : \"d3444455-mike-4271-b6ea-e499cc0cab46\",\n"
                                                       "\"home_account_id\" : \"60406d5d-mike-41e1-aa70-e97501076a22\",\n"
                                                       "\"user_id\" : \"mike@contoso.com\"\n"
                                                       "}]}"]];
    ADAuthenticationError *error = nil;

    XCTAssertNil([ADEnrollmentGateway enrollmentIdForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22" error:&error]);
    XCTAssertNil(error);

}

- (void)testintuneMAMResource_whenResourceExistsForHost_shouldSucceed
{
    ADAuthenticationError *error = nil;
    XCTAssert([@"https://www.microsoft.com/intune" isEqualToString: [ADEnrollmentGateway intuneMAMResource:[NSURL URLWithString:@"https://login.microsoftonline.com/common"] error:&error]]);
    XCTAssertNil(error);

}

- (void)testintuneMAMResource_whenResourceDoesNotForHost_shouldFailWithoutError
{
    ADAuthenticationError *error = nil;
    XCTAssertNil([ADEnrollmentGateway intuneMAMResource:[NSURL URLWithString:@"https://login.notMicrosoft.com/common"] error:&error]);
    XCTAssertNil(error);
}

- (void)testintuneMAMResource_whenResourceJSONIsCorrupt_shouldFailWithError
{
    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:@"corruptedJSON"];
    ADAuthenticationError *error = nil;
    XCTAssertNil([ADEnrollmentGateway intuneMAMResource:[NSURL URLWithString:@"https://login.microsoftonline.com"] error:&error]);
    XCTAssertNotNil(error);
}

- (void)testintuneMAMResource_whenResourceJSONStructureIsIncorrect_shouldFailWithError
{
    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:@"[]"];
    ADAuthenticationError *error = nil;
    XCTAssertNil([ADEnrollmentGateway intuneMAMResource:[NSURL URLWithString:@"https://login.microsoftonline.com"] error:&error]);
    XCTAssertNotNil(error);
}

- (void)testintuneMAMResource_whenResourceJSONIsEmpty_shouldReturnNilWithoutError
{
    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:@"{}"];
    ADAuthenticationError *error = nil;
    XCTAssertNil([ADEnrollmentGateway intuneMAMResource:[NSURL URLWithString:@"https://login.microsoftonline.com/common"] error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForHomeAccountIdUserId_whenFoundByEnrollmentId_shouldReturnEnrollmentId
{
    ADAuthenticationError *error = nil;
    XCTAssertNotNil([ADEnrollmentGateway enrollmentIDForHomeAccountId:@"60406d5d-mike-41e1-aa70-e97501076a22"  userID:@"user_id_not_exist" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForHomeAccountIdUserId_whenNotFoundByEnrollmentId_shouldFallbackToUserId
{
    ADAuthenticationError *error = nil;
    XCTAssertNotNil([ADEnrollmentGateway enrollmentIDForHomeAccountId:@"account_id_not_exist"  userID:@"mike@contoso.com" error:&error]);
    XCTAssertNil(error);
}

- (void)testEnrollmentIDForHomeAccountIdUserId_whenNotFoundByEitherEnrollmentIdOrUserId_shouldFallbackToWhateverAvailable
{
    ADAuthenticationError *error = nil;
    XCTAssertNotNil([ADEnrollmentGateway enrollmentIDForHomeAccountId:@"account_id_not_exist"  userID:@"user_id_not_exist" error:&error]);
    XCTAssertNil(error);
}

@end
