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
#import "XCTestCase+TestHelperMethods.h"
#import "../ADALiOS/ADAuthenticationParameters+Internal.h"

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
    [self adTestBegin:ADAL_LOG_LEVEL_ERROR];
    // Runs before each test case. Just in case, set them to nil.
    mParameters = nil;
    mError = nil;
}

- (void)tearDown
{
    //Runs after each test case. Clean up to ensure that the memory is freed before the other test:
    mParameters = nil;
    mError = nil;
    [self adTestEnd];
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
    static volatile int completion = 0;
    [self adCallAndWaitWithFile:@"" __FILE__ line:sourceLine completionSignal:&completion block:^
    {
        //The asynchronous call:
        [ADAuthenticationParameters parametersFromResourceUrl:resource
                                              completionBlock:^(ADAuthenticationParameters * par, ADAuthenticationError* err)
         {
             //Fill in the class members with the result:
             mParameters = par;
             mError = err;
             ASYNC_BLOCK_COMPLETE(completion);
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
-(void) verifyWithAuthority: (NSString*) expectedAuthority
{
    XCTAssertNotNil(mParameters, "Valid parameters should have been extracted.");
    XCTAssertNil(mError, "No error should be issued in this test. Details: %@", mError.errorDetails);
    XCTAssertNotNil(mParameters.authority, "A valid authority should be returned");
    ADAssertStringEquals(mParameters.authority, expectedAuthority);
}

/* Verifies correct handling when the resource cannot be reached */
- (void) testParametersFromResourceURLNoResponse
{
    NSURL* resource = [[NSURL alloc] initWithString:@"https://noneistingurl12345676789.com"];
    
    [self callAsynchronousCreator:resource line:__LINE__];
    XCTAssertNil(mParameters, "No parameters should be extracted from non-existing resource.");
    XCTAssertNotNil(mError, "Error should be set.");
    [self adAssertValidText:mError.errorDetails message:@"The error should have details."];
}


- (void) testParametersFromResourceURLParametersPositiveCase
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    //HTTP
    NSURL* resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    [self callAsynchronousCreator:resourceUrl line:__LINE__];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];

    //HTTPS
    resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    [self callAsynchronousCreator:resourceUrl line:__LINE__];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];
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
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
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
    [self verifyWithAuthority:@"https://www.example.com"];
    
    NSDictionary* headerFields2 = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                              forKey:@"www-AUTHEnticate"];//Capital
    NSHTTPURLResponse* response2 = [[NSHTTPURLResponse alloc] initWithURL:url
                                                               statusCode:401
                                                              HTTPVersion:@"1.1"
                                                             headerFields:headerFields2];
    mParameters = [ADAuthenticationParameters parametersFromResponse:response2 error:&error];
    XCTAssertNil(error);
    [self verifyWithAuthority:@"https://www.example.com"];

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

-(void) validateExtractChallenge: (NSString*) challenge
                       authority: (NSString*) expectedAuthority
                        resource: (NSString*) expectedResource
                            line: (int) sourceLine
{
    ADAuthenticationError* error;
    NSDictionary* params = [ADAuthenticationParameters extractChallengeParameters:challenge error:&error];
    if (params)
    {
        [self adAssertStringEquals:[params objectForKey:OAuth2_Authorization_Uri]
                  stringExpression:@"extracted authority"
                          expected:expectedAuthority
                              file:__FILE__
                              line:sourceLine];
        [self adAssertStringEquals:[params objectForKey:OAuth2_Resource_Id]
                  stringExpression:@"extracted resource"
                          expected:expectedResource
                              file:__FILE__
                              line:sourceLine];
    }
    else
    {
        if (!error)
        {
            [self recordFailureWithDescription:@"Record should be returned here." inFile:@"" __FILE__ atLine:sourceLine expected:NO];
        }
        //init will return nil if the bearer format is incorrect:
        if (expectedAuthority)
        {
            [self recordFailureWithDescription:@"Failed to parse the Bearer header." inFile:@"" __FILE__ atLine:sourceLine expected:NO];
        }
    }
}

-(void) testInternalInit
{
    ADAuthenticationParameters* params = [ADAuthenticationParameters alloc];
    XCTAssertThrowsSpecificNamed([params initInternalWithParameters:0 error:nil],
                                 NSException, NSInvalidArgumentException, "Exception should be thrown in this case");
    [self validateExtractChallenge:@"Bearerauthorization_uri=\"abc\", resource_id=\"foo\"" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer foo" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer foo=bar" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer foo=\"bar\"" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer foo=\"bar" authority:nil resource:nil line:__LINE__];//Missing second quote
    [self validateExtractChallenge:@"Bearer foo=\"bar\"," authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer   authorization_uri=\"https://login.windows.net/common\""
                                authority:@"https://login.windows.net/common" resource:nil line:__LINE__];
    //More commas:
    [self validateExtractChallenge:@"Bearer authorization_uri=\"https://login.windows.net/common\""
                         authority:@"https://login.windows.net/common"
                          resource:nil
                              line:__LINE__];
    [self validateExtractChallenge:@"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\""
                         authority:@"https://login.windows.net/common"
                          resource:@"foo"
                              line:__LINE__];
    [self validateExtractChallenge:@"Bearer authorization_uri=\"\",resource_id=\"foo\"" authority:nil resource:@"foo" line:__LINE__];

    //Pass an attribute, whose value contains commas:
    [self validateExtractChallenge:@"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\""
                         authority:@"https://login.windows.net/common"
                          resource:@"foo"
                              line:__LINE__];
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
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    ADAuthenticationError* error;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"foo.com\", anotherParam=\"Indeed, another param=5\" "
                                                                            error:&error];
    XCTAssertNotNil(params);
    XCTAssertNil(error);
    XCTAssertNil(params.resource);
    ADAssertStringEquals(params.authority, @"https://login.windows.net/common");
    
    NSDictionary* extractedParameters = [params getExtractedParameters];
    XCTAssertNotNil(extractedParameters);
    ADAssertStringEquals([extractedParameters objectForKey:@"anotherParam"], @"Indeed, another param=5");
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
