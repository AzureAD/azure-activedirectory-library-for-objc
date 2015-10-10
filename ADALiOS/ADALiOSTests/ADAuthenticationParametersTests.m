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

#import <XCTest/XCTest.h>
#import <ADALiOS/ADAuthenticationParameters.h>
#import <ADALiOS/ADAuthenticationSettings.h>
#import "XCTestCase+TestHelperMethods.h"
#import "../ADALiOS/ADAuthenticationParameters+Internal.h"
#import "ADTestURLConnection.h"

@interface ADAuthenticationParametersTests : XCTestCase
{
    @private
    ADAuthenticationParameters* mParameters;
    ADAuthenticationError* mError;//Set up by asynchronous calls
}

@end

@implementation ADAuthenticationParametersTests

- (void)setUp
{
    [super setUp];
    // Runs before each test case. Just in case, set them to nil.
    mParameters = nil;
    mError = nil;
    [ADAuthenticationSettings sharedInstance].requestTimeOut = 5;
}

- (void)tearDown
{
    //Runs after each test case. Clean up to ensure that the memory is freed before the other test:
    mParameters = nil;
    mError = nil;
    [super tearDown];
}

- (void)testNew
{
    XCTAssertThrows([ADAuthenticationParameters new], "Creation with new should throw.");
}
 

- (void) testInit
{
    mParameters = [ADAuthenticationParameters alloc];
    XCTAssertThrows([mParameters init], "Default init method should throw.");
}

/* Helper function to fascilitate calling of the asynchronous creator, waiting for the response
 and setting the test class members according to the result. */
-(void) callAsynchronousCreator: (NSURL*) resource
                           line: (int) sourceLine
{
    //Reset
    mParameters = nil;
    mError = nil;
    __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ semaphore:sem block:^
    {
        //The asynchronous call:
        [ADAuthenticationParameters parametersFromResourceUrl:resource
                                              completionBlock:^(ADAuthenticationParameters * par, ADAuthenticationError* err)
         {
             //Fill in the class members with the result:
             mParameters = par;
             mError = err;
            dispatch_semaphore_signal(sem);
         }];
    }];
    if (!!mParameters == !!mError)//Exactly one of these two should be set
    {
        [self recordFailureWithDescription:@"Incorrect values of parameters and error."
                                    inFile:@"" __FILE__
                                    atLine:sourceLine
                                  expected:NO];
    }
}


/* A wrapper around ADTestHelper::validateCreatorForInvalidArgument, passing the test class members*/
-(void) adValidateFactoryForInvalidArgument: (NSString*) argument
                                    error: (ADAuthenticationError*) error
{
    [self adValidateFactoryForInvalidArgument:argument
                             returnedObject:mParameters
                                      error:error];
}

/* A wrapper around ADTestHelper::validateCreatorForInvalidArgument, passing the test class members*/
-(void) adValidateFactoryForInvalidArgument: (NSString*) argument
{
    [self adValidateFactoryForInvalidArgument:argument
                                      error:mError];
}

- (void) testParametersFromResourceURLParametersNil
{
    [self callAsynchronousCreator:nil line:__LINE__];
    [self adValidateFactoryForInvalidArgument:@"resourceUrl"];

    //Pass nil for the completionBlock:
    NSURL* resource = [[NSURL alloc] initWithString:@"https://mytodolist.com"];
    XCTAssertThrowsSpecificNamed([ADAuthenticationParameters parametersFromResourceUrl: resource completionBlock:nil],
        NSException, NSInvalidArgumentException, "Null argument should throw an invalid argument exception. At: %s", __PRETTY_FUNCTION__);
}

/* validates a successful parameters extraction */
#define VERIFY_AUTHORITY(_expectedAuthority) \
{ \
    XCTAssertNotNil(mParameters, "Valid parameters should have been extracted."); \
    XCTAssertNil(mError, "No error should be issued in this test. Details: %@", mError.errorDetails); \
    XCTAssertNotNil(mParameters.authority, "A valid authority should be returned"); \
    XCTAssertEqualObjects(mParameters.authority, _expectedAuthority); \
}

/* Verifies correct handling when the resource cannot be reached */
- (void) testParametersFromResourceURLNoResponse
{
    NSURL* resource = [[NSURL alloc] initWithString:@"https://noneistingurl12345676789.com"];
    [ADTestURLConnection addNotFoundResponseForURLString:@"https://noneistingurl12345676789.com?x-client-Ver=" ADAL_VERSION_STRING];
    [self callAsynchronousCreator:resource line:__LINE__];
    XCTAssertNil(mParameters, "No parameters should be extracted from non-existing resource.");
    XCTAssertNotNil(mError, "Error should be set.");
    XCTAssertFalse([NSString adIsStringNilOrBlank:mError.errorDetails], @"Error should provide details.");
}


- (void) testParametersFromResourceURLParametersPositiveCase
{
    //HTTP
    NSURL* resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"http://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                                            responseURLString:@"http://contoso.com"
                                                                 responseCode:HTTP_UNAUTHORIZED
                                                             httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                             dictionaryAsJSON:@{}];
    
    [ADTestURLConnection addResponse:response];
    
    [self callAsynchronousCreator:resourceUrl line:__LINE__];
    VERIFY_AUTHORITY(@"https://login.windows.net/omercantest.onmicrosoft.com");
}

-(void) testParametersFromAnauthorizedResponseNilParameter
{
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"response" error:error];
    
    //Now test that the method can handle passing nil for error:
    mParameters = [ADAuthenticationParameters parametersFromResponse:nil error:nil];
    XCTAssertNil(mParameters, "No parameters should be created.");
}

-(void)testParametersFromResponseAuthenticateHeaderNilParameter
{
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:&error];
    XCTAssertNil(mParameters);
    XCTAssertNotNil(error);
    
    //Now test that the method can handle passing nil for error:
    mParameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:nil];
    XCTAssertNil(mParameters, "No parameters should be created.");
}

-(void)expectedError: (ADAuthenticationError*)error
                line: (int) sourceLine
{
    if (!error)
    {
        [self recordFailureWithDescription:@"Error expected" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    if (![error.domain isEqualToString:ADUnauthorizedResponseErrorDomain])
    {
        [self recordFailureWithDescription:@"Wrong domain" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    if ([NSString adIsStringNilOrBlank:error.errorDetails])
    {
        [self recordFailureWithDescription:@"Empty error details." inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    if (![error.errorDetails adContainsString:@"Unauthorized"])
    {
        [self recordFailureWithDescription:@"Wrong error details." inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
}

-(void)testParametersFromResponseMissingHeader
{
    NSHTTPURLResponse* response = [NSHTTPURLResponse new];
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:response error:&error];
    XCTAssertNil(mParameters, "Parameters object returned on a missing header.");
    [self expectedError:error line:__LINE__];
    
    //Now test that the method can handle passing nil for error:
    mParameters = [ADAuthenticationParameters parametersFromResponse:response error:nil];
    XCTAssertNil(mParameters, "No parameters should be created.");
}

-(void)testParametersFromResponseDifferentHeaderCase
{
    //HTTP headers are case-insensitive. This test validates that the underlying code is aware:
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary* headerFields1 = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                              forKey:@"WWW-AUTHENTICATE"];//Capital
    NSHTTPURLResponse* response1 = [[NSHTTPURLResponse alloc] initWithURL:url
                                                               statusCode:401
                                                              HTTPVersion:@"1.1"
                                                             headerFields:headerFields1];
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:response1 error:&error];
    XCTAssertNil(error);
    VERIFY_AUTHORITY(@"https://www.example.com");
    
    NSDictionary* headerFields2 = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                              forKey:@"www-AUTHEnticate"];//Capital
    NSHTTPURLResponse* response2 = [[NSHTTPURLResponse alloc] initWithURL:url
                                                               statusCode:401
                                                              HTTPVersion:@"1.1"
                                                             headerFields:headerFields2];
    mParameters = [ADAuthenticationParameters parametersFromResponse:response2 error:&error];
    XCTAssertNil(error);
    VERIFY_AUTHORITY(@"https://www.example.com");
}

/* Checks that the correct error is returned when extractChallenge is called with an invalid header text */
-(void)extractChallengeWithInvalidHeader: (NSString*) text
                                    line: (int) sourceLine
{
    //Empty string:
    ADAuthenticationError* error;
    NSDictionary* result = [ADAuthenticationParameters extractChallengeParameters:text error:&error];
    if (result)
    {
        [self recordFailureWithDescription:@"Parsed invalid header" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    [self expectedError:error line:sourceLine];
    if (AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT != error.code)
    {
        [self recordFailureWithDescription:@"Wrong error code" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
}

-(void)testExtractChallengeParametersInvalidBearer
{
    ADAuthenticationError* error;
    XCTAssertNil([ADAuthenticationParameters extractChallengeParameters:nil error:&error]);
    XCTAssertNotNil(error);

    //No Bearer, or Bearer is not a word:
    [self extractChallengeWithInvalidHeader:@"" line:__LINE__];//Empty string
    [self extractChallengeWithInvalidHeader:@"   " line:__LINE__];//Blank string:
    [self extractChallengeWithInvalidHeader:@"BearerBlahblah" line:__LINE__];//Starts with Bearer, but it is not
    [self extractChallengeWithInvalidHeader:@"Bearer,, " line:__LINE__];
    [self extractChallengeWithInvalidHeader:@"Bearer test string" line:__LINE__];
}
- (NSString*)extract:(NSString*)key
           challenge:(NSString*)challenge
               error:(ADAuthenticationError* __autoreleasing *)error
{
    NSDictionary* params = [ADAuthenticationParameters extractChallengeParameters:challenge error:error];
    if (!params)
    {
        return nil;
    }
    
    return [params objectForKey:key];
}

- (void)testParameterlessInit
{
    ADAuthenticationParameters* params = [ADAuthenticationParameters alloc];
    XCTAssertThrowsSpecificNamed([params initInternalWithParameters:0 error:nil],
                                 NSException, NSInvalidArgumentException, "Exception should be thrown in this case");
}

#define VALIDATE_EXTRACT(_challenge, _expected, _key, _friendlyKey) { \
    ADAuthenticationError* _ERROR = nil; \
    NSString* _extracted = [self extract:_key challenge:_challenge error:&_ERROR]; \
    if (_expected) { XCTAssertNotNil(_extracted, @"expected a " #_friendlyKey " from " #_challenge ": %@", _challenge); } \
    else { XCTAssertNil(_extracted, @"Did not expect a " #_friendlyKey" from " #_challenge ": %@", _challenge); }\
    if (_extracted) { \
        XCTAssertEqualObjects(_extracted, _expected, \
                              @"failed to extract " #_friendlyKey " (%@) from " #_challenge " (%@) does not match expected " #_friendlyKey " (%@)", \
                                _extracted, _challenge, _expected); \
    } \
}

#define VALIDATE_EXTRACT_AUTHORITY(_challenge, _expectedAuthority) VALIDATE_EXTRACT(_challenge, _expectedAuthority, OAuth2_Authorization_Uri, authority)
#define VALIDATE_EXTRACT_RESOURCE(_challenge, _expectedResource) VALIDATE_EXTRACT(_challenge, _expectedResource, OAuth2_Resource_Id, resource)

- (void)testInvalidAuthorities
{
    NSString* invalidChallenge1 = @"Bearerauthorization_uri=\"abc\", resource_id=\"foo\"";
    VALIDATE_EXTRACT_AUTHORITY(invalidChallenge1, nil);
    VALIDATE_EXTRACT_RESOURCE(invalidChallenge1, nil);
    
    NSString* invalidChallenge2 = @"Bearer foo";
    VALIDATE_EXTRACT_AUTHORITY(invalidChallenge2, nil);
    VALIDATE_EXTRACT_RESOURCE(invalidChallenge2, nil);
    
    NSString* invalidChallenge3 = @"Bearer foo=bar";
    VALIDATE_EXTRACT_AUTHORITY(invalidChallenge3, nil);
    VALIDATE_EXTRACT_RESOURCE(invalidChallenge3, nil);
    
    NSString* invalidChallenge5 = @"Bearer foo=\"bar"; // Missing second quote
    VALIDATE_EXTRACT_AUTHORITY(invalidChallenge5, nil);
    VALIDATE_EXTRACT_RESOURCE(invalidChallenge5, nil);
    
    NSString* invalidChallenge6 = @"Bearer foo=\"bar\",";
    VALIDATE_EXTRACT_AUTHORITY(invalidChallenge6, nil);
    VALIDATE_EXTRACT_RESOURCE(invalidChallenge6, nil);
}

- (void)testValidAuthorityNoResource
{
    NSString* validAuthorityNoResource1 = @"Bearer   authorization_uri=\"https://login.windows.net/common\"";
    VALIDATE_EXTRACT_AUTHORITY(validAuthorityNoResource1, @"https://login.windows.net/common");
    VALIDATE_EXTRACT_RESOURCE(validAuthorityNoResource1, nil);
    
    NSString* validAuthorityNoResource2 = @"Bearer authorization_uri=\"https://login.windows.net/common\"";
    VALIDATE_EXTRACT_AUTHORITY(validAuthorityNoResource2, @"https://login.windows.net/common");
    VALIDATE_EXTRACT_RESOURCE(validAuthorityNoResource2, nil);
}
    
- (void)testValidAuthorityAndResource
{
    NSString* validAuthorityAndResource1 = @"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\"";
    VALIDATE_EXTRACT_AUTHORITY(validAuthorityAndResource1, @"https://login.windows.net/common");
    VALIDATE_EXTRACT_RESOURCE(validAuthorityAndResource1, @"foo");
    
    NSString* validAuthorityAndResource2 = @"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\"";
    VALIDATE_EXTRACT_AUTHORITY(validAuthorityAndResource2, @"https://login.windows.net/common");
    VALIDATE_EXTRACT_RESOURCE(validAuthorityAndResource2, @"foo");
}

- (void)testValidResourceNoAuthority
{
    NSString* validResourceNoAuthority1 = @"Bearer authorization_uri=\"\",resource_id=\"foo\"";
    VALIDATE_EXTRACT_AUTHORITY(validResourceNoAuthority1, nil);
    VALIDATE_EXTRACT_RESOURCE(validResourceNoAuthority1, @"foo");
}

-(void) validateFactoryForBadHeader: (NSString *) header
                               line: (int) sourceLine
{
    ADAuthenticationError* error;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:header error:&error];
    XCTAssertNil(params);
    [self expectedError:error line:sourceLine];
    ADAssertLongEquals(error.code, AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT);
}

-(void) testParametersFromResponseAuthenticateHeaderInvalid
{
    [self validateFactoryForBadHeader:@"Bearer foo=bar" line:__LINE__];
    [self validateFactoryForBadHeader:@"Bearer = , = , "  line:__LINE__];
    [self validateFactoryForBadHeader:@"Bearer =,=,=" line:__LINE__];
}

-(void) testParametersFromResponseAuthenticateHeaderValid
{
    ADAuthenticationError* error;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"foo.com\", anotherParam=\"Indeed, another param=5\" "
                                                                            error:&error];
    XCTAssertNotNil(params);
    XCTAssertNil(error);
    XCTAssertNil(params.resource);
    XCTAssertEqualObjects(params.authority, @"https://login.windows.net/common");
    
    NSDictionary* extractedParameters = [params getExtractedParameters];
    XCTAssertNotNil(extractedParameters);
    XCTAssertEqualObjects([extractedParameters objectForKey:@"anotherParam"], @"Indeed, another param=5");
}

-(void) testParametersFromResponseAuthenticateHeaderBadUrl
{
    NSString* badUrl = @".\\..\\windows\\system32\\drivers\\etc\\host";
    ADAuthenticationError* error;
    ADAuthenticationParameters* params =
        [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:
            [NSString stringWithFormat:@"Bearer authorization_uri=\"%@\"", badUrl]
                                                                       error:&error];
    XCTAssertNil(params);
    XCTAssertNotNil(error);
}


@end
