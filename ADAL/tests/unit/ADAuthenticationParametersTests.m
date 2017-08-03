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
#import "ADAuthenticationParameters.h"
#import "ADAuthenticationSettings.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADAuthenticationParameters+Internal.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"

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
    ADAuthenticationParameters* params = [ADAuthenticationParameters alloc];
    XCTAssertThrows([params init], "Default init method should throw.");
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
    [ADTestURLSession addNotFoundResponseForURLString:@"https://noneistingurl12345676789.com?x-client-Ver=" ADAL_VERSION_STRING];
    [self callAsynchronousCreator:resource line:__LINE__];
    XCTAssertNil(mParameters, "No parameters should be extracted from non-existing resource.");
    XCTAssertNotNil(mError, "Error should be set.");
    XCTAssertFalse([NSString adIsStringNilOrBlank:mError.errorDetails], @"Error should have details.");
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
    
    [ADTestURLSession addResponse:response];
    [self callAsynchronousCreator:resourceUrl line:__LINE__];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];

    //HTTPS
    resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    response = [ADTestURLResponse requestURLString:@"https://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:HTTP_UNAUTHORIZED
                                                     httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                     dictionaryAsJSON:@{}];
    
    [ADTestURLSession addResponse:response];
    [self callAsynchronousCreator:resourceUrl line:__LINE__];
    [self verifyWithAuthority:@"https://login.windows.net/omercantest.onmicrosoft.com"];
}

-(void) testParametersFromAnauthorizedResponseNilParameter
{
    ADAuthenticationError* error;//A local variable is needed for __autoreleasing reference pointers.
    mParameters  = [ADAuthenticationParameters parametersFromResponse:nil error:&error];
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
    if (![error.domain isEqualToString:ADAuthenticationErrorDomain])
    {
        [self recordFailureWithDescription:@"Wrong domain" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    if ([NSString adIsStringNilOrBlank:error.errorDetails])
    {
        [self recordFailureWithDescription:@"Empty error details." inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    if (![error.errorDetails containsString:@"Unauthorized"])
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
                                                              forKey:@"WWW-AUTHENTICATE"];//Uppercase
    NSHTTPURLResponse* response1 = [[NSHTTPURLResponse alloc] initWithURL:url
                                                               statusCode:401
                                                              HTTPVersion:@"1.1"
                                                             headerFields:headerFields1];
    ADAuthenticationError* error = nil;//A local variable is needed for __autoreleasing reference pointers.
    mParameters = [ADAuthenticationParameters parametersFromResponse:response1 error:&error];
    XCTAssertNil(error);
    [self verifyWithAuthority:@"https://www.example.com"];
    
    NSDictionary* headerFields2 = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                              forKey:@"www-AUTHEnticate"];//Partially uppercase
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
    ADAuthenticationError* error = nil;
    NSDictionary* result = [ADAuthenticationParameters extractChallengeParameters:text error:&error];
    if (result)
    {
        [self recordFailureWithDescription:@"Parsed invalid header" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
    [self expectedError:error line:sourceLine];
    if (AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT != error.code)
    {
        [self recordFailureWithDescription:@"Wrong error code" inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
}

-(void)testExtractChallengeParametersInvalidBearer
{
    ADAuthenticationError* error = nil;
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
    ADAuthenticationError* error = nil;
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
    [self validateExtractChallenge:@"Bearerauthorization_uri=\"abc\", resource_id=\"something\"" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer something" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer something=bar" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer something=\"bar\"" authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer something=\"bar" authority:nil resource:nil line:__LINE__];//Missing second quote
    [self validateExtractChallenge:@"Bearer something=\"bar\"," authority:nil resource:nil line:__LINE__];
    [self validateExtractChallenge:@"Bearer   authorization_uri=\"https://login.windows.net/common\""
                                authority:@"https://login.windows.net/common" resource:nil line:__LINE__];
    //More commas:
    [self validateExtractChallenge:@"Bearer authorization_uri=\"https://login.windows.net/common\""
                         authority:@"https://login.windows.net/common"
                          resource:nil
                              line:__LINE__];
    [self validateExtractChallenge:@"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\""
                         authority:@"https://login.windows.net/common"
                          resource:@"something"
                              line:__LINE__];
    [self validateExtractChallenge:@"Bearer authorization_uri=\"\",resource_id=\"something\"" authority:nil resource:@"something" line:__LINE__];

    //Pass an attribute, whose value contains commas:
    [self validateExtractChallenge:@"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\""
                         authority:@"https://login.windows.net/common"
                          resource:@"something"
                              line:__LINE__];
}

-(void) validateFactoryForBadHeader: (NSString *) header
                               line: (int) sourceLine
{
    ADAuthenticationError* error = nil;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:header error:&error];
    XCTAssertNil(params);
    [self expectedError:error line:sourceLine];
    ADAssertLongEquals(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

-(void) testParametersFromResponseAuthenticateHeaderInvalid
{
    [self validateFactoryForBadHeader:@"Bearer something=bar" line:__LINE__];
    [self validateFactoryForBadHeader:@"Bearer = , = , "  line:__LINE__];
    [self validateFactoryForBadHeader:@"Bearer =,=,=" line:__LINE__];
}

-(void) testParametersFromResponseAuthenticateHeaderValid
{
    ADAuthenticationError* error = nil;
    ADAuthenticationParameters* params = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"something.com\", anotherParam=\"Indeed, another param=5\" "
                                                                            error:&error];
    XCTAssertNotNil(params);
    XCTAssertNil(error);
    XCTAssertNil(params.resource);
    ADAssertStringEquals(params.authority, @"https://login.windows.net/common");
    
    NSDictionary* extractedParameters = [params extractedParameters];
    XCTAssertNotNil(extractedParameters);
    ADAssertStringEquals([extractedParameters objectForKey:@"anotherParam"], @"Indeed, another param=5");
}

-(void) testParametersFromResponseAuthenticateHeaderBadUrl
{
    NSString* badUrl = @".\\..\\windows\\system32\\drivers\\etc\\host";
    ADAuthenticationError* error = nil;
    ADAuthenticationParameters* params =
        [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:
            [NSString stringWithFormat:@"Bearer authorization_uri=\"%@\"", badUrl]
                                                                       error:&error];
    XCTAssertNil(params);
    XCTAssertNotNil(error);
}


@end
