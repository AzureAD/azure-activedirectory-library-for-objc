// Created by Boris Vidolov on 10/10/13.
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
    [self adTestBegin];
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
{
    //The signal to denote completion:
    __block dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    XCTAssertTrue(completed, "Failed to create a semaphore");
    
    [ADAuthenticationParameters parametersFromResourceUrl:resource
                                          completionBlock:^(ADAuthenticationParameters * par, ADAuthenticationError* err)
     {
         //Fill in the class members with the result:
         mParameters = par;
         mError = err;
         dispatch_semaphore_signal(completed);//Tell the test to move on
     }];
    
    //Waits for the callback:
    if (dispatch_semaphore_wait(completed, dispatch_time(DISPATCH_TIME_NOW, 10*NSEC_PER_SEC)))
    {
        XCTFail("Timeout while getting the 401 request.");
    }
}


/* A wrapper around ADTestHelper::validateCreatorForInvalidArgument, passing the test class members*/
-(void) validateFactoryForInvalidArgument: (NSString*) argument
                                    error: (ADAuthenticationError*) error
{
    [self validateFactoryForInvalidArgument:argument
                             returnedObject:mParameters
                                      error:error];
}

/* A wrapper around ADTestHelper::validateCreatorForInvalidArgument, passing the test class members*/
-(void) validateFactoryForInvalidArgument: (NSString*) argument
{
    [self validateFactoryForInvalidArgument:argument
                                      error:mError];
}

- (void) testParametersFromResourceURLParametersNil
{
    [self callAsynchronousCreator:nil];
    [self validateFactoryForInvalidArgument:@"resourceUrl"];

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
    
    [self callAsynchronousCreator:resource];
    XCTAssertNil(mParameters, "No parameters should be extracted from non-existing resource.");
    XCTAssertNotNil(mError, "Error should be set.");
    [self assertValidText:mError.errorDetails message:@"The error should have details."];
}


- (void) testParametersFromResourceURLParametersPositiveCase
{
    //HTTP
    NSURL* resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    [self callAsynchronousCreator:resourceUrl];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];

    //HTTPS
    resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    [self callAsynchronousCreator:resourceUrl];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];
}

-(void) testParametersFromAnauthorizedResponseNilParameter
{
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:nil error:&error];
    [self validateFactoryForInvalidArgument:@"response" error:error];
    
    //Now test that the method can handle passing nil for error:
    mParameters = [ADAuthenticationParameters parametersFromResponse:nil error:nil];
    XCTAssertNil(mParameters, "No parameters should be created.");
}

-(void)testParametersFromResponseAuthenticateHeaderNilParameter
{
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:&error];
    [self validateFactoryForInvalidArgument:@"authenticateHeader" error:error];
    
    //Now test that the method can handle passing nil for error:
    mParameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:nil];
    XCTAssertNil(mParameters, "No parameters should be created.");
}

-(void)expectedError:(ADAuthenticationError*)error
{
    XCTAssertNotNil(error, "Error expected.");
    XCTAssertEqual(error.domain, ADUnauthorizedResponseErrorDomain, "Wrong domain");
    XCTAssertFalse([NSString isStringNilOrBlank:error.errorDetails], "Empty error details.");
    XCTAssertTrue([error.errorDetails containsString:@"Unauthorized"], "Wrong error details.");
}

-(void)testParametersFromResponseMissingHeader
{
    NSHTTPURLResponse* response = [NSHTTPURLResponse new];
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:response error:&error];
    XCTAssertNil(mParameters, "Parameters object returned on a missing header.");
    [self expectedError:error];
    
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
{
    //Empty string:
    ADAuthenticationError* error;
    long result = [ADAuthenticationParameters extractChallenge:text error:&error];
    XCTAssertTrue(result < 0, "Nil should be returned for the error case: %@", text);
    [self expectedError:error];
    ADAssertLongEquals(error.code, AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT);
}

-(void)testExtractChallengeInvalid
{
    ADAuthenticationError* error;
    XCTAssertThrowsSpecificNamed([ADAuthenticationParameters extractChallenge:nil error:&error],
                                 NSException, NSInvalidArgumentException, "Exception should be thrown in this case");

    //No Bearer, or Bearer is not a word:
    [self extractChallengeWithInvalidHeader:@""];//Empty string
    [self extractChallengeWithInvalidHeader:@"   "];//Blank string:
    [self extractChallengeWithInvalidHeader:@"BearerBlahblah"];//Starts with Bearer, but it is not
    [self extractChallengeWithInvalidHeader:@"Bearer,, "];
}

-(void)testExtractChallengeValid
{
    ADAuthenticationError* error;
    NSString* bearer = @"Bearer test string";
    long result = [ADAuthenticationParameters extractChallenge:@"Bearer test string" error:&error];
    ADAssertStringEquals([bearer substringFromIndex:result], @"test string");
    XCTAssertNil(error);
}

-(void) testInitializationWithChallenge: (NSString*) challenge
                              authority: (NSString*) expectedAuthority
                               resource: (NSString*) expectedResource
{
    ADAuthenticationParameters* params = [ADAuthenticationParameters alloc];
    params = [params initInternalWithChallenge:challenge start:0];
    if (params)
    {
        ADAssertStringEquals(params.authority, expectedAuthority);
        ADAssertStringEquals(params.resource, expectedResource);
    }
    else
    {
        //init will return nil if the bearer format is incorrect:
        XCTAssertNil(expectedAuthority);
    }
}

-(void) testInternalInit
{
    ADAuthenticationParameters* params = [ADAuthenticationParameters alloc];
    XCTAssertThrowsSpecificNamed([params initInternalWithChallenge:nil start:0],
                                 NSException, NSInvalidArgumentException, "Exception should be thrown in this case");
    
    [self testInitializationWithChallenge:@"foo" authority:nil resource:nil];
    [self testInitializationWithChallenge:@"foo=bar" authority:nil resource:nil];
    [self testInitializationWithChallenge:@"foo=\"bar\"" authority:nil resource:nil];
    [self testInitializationWithChallenge:@"foo=\"bar" authority:nil resource:nil];//Missing second quote
    [self testInitializationWithChallenge:@"foo=\"bar\"," authority:nil resource:nil];
    [self testInitializationWithChallenge:@"  authorization_uri=\"https://login.windows.net/common\""
                                authority:@"https://login.windows.net/common" resource:nil];
    //More commas:
    [self testInitializationWithChallenge:@",authorization_uri=\"https://login.windows.net/common\","
                                authority:@"https://login.windows.net/common"
                                 resource:nil];
    [self testInitializationWithChallenge:@",authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\""
                                authority:@"https://login.windows.net/common"
                                 resource:@"foo"];
    [self testInitializationWithChallenge:@",authorization_uri=\"\",resource_id=\"foo\"" authority:nil resource:@"foo"];

    //Pass an attribute, whose value contains commas:
    [self testInitializationWithChallenge:@" error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"foo\""
                                authority:@"https://login.windows.net/common"
                                 resource:@"foo"];
}

-(void) validateFactoryForBadHeader:(NSString *) header
{
    ADAuthenticationError* error;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:header error:&error];
    XCTAssertNil(params);
    [self expectedError:error];
    ADAssertLongEquals(error.code, AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT);
}

-(void) testParametersFromResponseAuthenticateHeaderInvalid
{
    [self validateFactoryForBadHeader:@"Bearer foo=bar"];
    [self validateFactoryForBadHeader:@"Bearer = , = , "];
    [self validateFactoryForBadHeader:@"Bearer =,=,="];
}

-(void) testParametersFromResponseAuthenticateHeaderValid
{
    ADAuthenticationError* error;
    ADAuthenticationParameters* params = params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"foo.com\", anotherParam=\"Indeed, another param=5\" "
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
