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

@interface ADAuthenticationParametersTests : ADTestCase

@end

@implementation ADAuthenticationParametersTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - Initialization

- (void)testNew_shouldThrow
{
    XCTAssertThrows([ADAuthenticationParameters new], "Creation with new should throw.");
}

- (void)testInit_shouldThrow
{
    XCTAssertThrows([[ADAuthenticationParameters alloc] init], "Default init method should throw.");
}

#pragma mark - parametersFromResourceUrl

- (void)testParametersFromResourceUrl_whenResourceUrlIsNil_shouldReturnNilParameters
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with nil resource should return error."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:nil completionBlock:^(ADAuthenticationParameters *parameters, ADAuthenticationError __unused *error)
     {
         XCTAssertNil(parameters);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenResourceUrlIsNil_shouldReturnError
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with nil resource should return error."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:nil completionBlock:^(ADAuthenticationParameters __unused *parameters, ADAuthenticationError *error)
     {
         XCTAssertNotNil(error);
         ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
         XCTAssertNil(error.protocolCode);
         ADAssertStringEquals(error.errorDetails, @"The argument 'resourceUrl' is invalid. Value:(null)");
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenCompletionBlockIsNil_shouldThrowException
{
    NSURL *resource = [[NSURL alloc] initWithString:@"https://mytodolist.com"];
    
    XCTAssertThrowsSpecificNamed([ADAuthenticationParameters parametersFromResourceUrl:resource completionBlock:nil], NSException, NSInvalidArgumentException);
}

- (void)testParametersFromResourceUrl_whenResourceUrlIsNotExist_shouldReturnNilParameters
{
    NSURL *resource = [[NSURL alloc] initWithString:@"https://noneistingurl12345676789.com"];
    [ADTestURLSession addNotFoundResponseForURLString:@"https://noneistingurl12345676789.com?x-client-Ver=" ADAL_VERSION_STRING];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with non existing resource should return error."];
    [ADAuthenticationParameters parametersFromResourceUrl:resource completionBlock:^(ADAuthenticationParameters *parameters, ADAuthenticationError __unused *error)
     {
         XCTAssertNil(parameters);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenResourceUrlIsNotExist_shouldReturnError
{
    NSURL *resource = [[NSURL alloc] initWithString:@"https://noneistingurl12345676789.com"];
    [ADTestURLSession addNotFoundResponseForURLString:@"https://noneistingurl12345676789.com?x-client-Ver=" ADAL_VERSION_STRING];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with non existing resource should return error."];
    [ADAuthenticationParameters parametersFromResourceUrl:resource completionBlock:^(ADAuthenticationParameters __unused *parameters, ADAuthenticationError *error)
     {
         XCTAssertNotNil(error);
         XCTAssertFalse([NSString adIsStringNilOrBlank:error.errorDetails], @"Error should have details.");
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpResourceUrlExists_shouldReturnAuthenticationParameters
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"http://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                                    responseURLString:@"http://contoso.com"
                                                         responseCode:HTTP_UNAUTHORIZED
                                                     httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                     dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADAuthenticationParameters *parameters, ADAuthenticationError __unused *error)
     {
         XCTAssertNotNil(parameters);
         XCTAssertNotNil(parameters.authority);
         XCTAssertEqualObjects(parameters.authority, @"https://login.windows.net/omercantest.onmicrosoft.com");
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpResourceUrlExists_shouldReturnNilError
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"http://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                                    responseURLString:@"http://contoso.com"
                                                         responseCode:HTTP_UNAUTHORIZED
                                                     httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                     dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADAuthenticationParameters __unused *parameters, ADAuthenticationError *error)
     {
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpsResourceUrlExists_shouldReturnAuthenticationParameters
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"https://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                 responseURLString:@"https://contoso.com"
                                      responseCode:HTTP_UNAUTHORIZED
                                  httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                  dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADAuthenticationParameters *parameters, ADAuthenticationError __unused *error)
     {
         XCTAssertNotNil(parameters);
         XCTAssertNotNil(parameters.authority);
         XCTAssertEqualObjects(parameters.authority, @"https://login.windows.net/omercantest.onmicrosoft.com");
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpsResourceUrlExists_shouldReturnNilError
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"https://testapi007.azurewebsites.net/api/WorkItem?x-client-Ver=" ADAL_VERSION_STRING
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:HTTP_UNAUTHORIZED
                                                     httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                     dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADAuthenticationParameters __unused *parameters, ADAuthenticationError *error)
     {
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

#pragma mark - parametersFromResponse

- (void)testParametersFromResponse_whenResponseNilErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters parametersFromResponse:nil error:&error];

    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The argument 'response' is invalid. Value:(null)");
}

- (void)testParametersFromResponse_whenResponseNilErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:nil error:&error];

    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseNilErrorPointerNil_shouldReturnNilParameters
{
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:nil error:nil];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithoutAuthenticateHeaderErrorPointerIsProvided_shouldReturnNilParameters
{
    NSHTTPURLResponse *response = [NSHTTPURLResponse new];
    ADAuthenticationError *error;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithoutAuthenticateHeaderErrorPointerIsProvided_shouldReturnError
{
    NSHTTPURLResponse *response = [NSHTTPURLResponse new];
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' is missing in the Unauthorized (401) response. Make sure that the resouce server supports OAuth2 protocol.");
}

- (void)testParametersFromResponse_whenResponseWithoutAuthenticateHeaderErrorPointerNil_shouldReturnNilParameters
{
    NSHTTPURLResponse *response = [NSHTTPURLResponse new];
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:response error:nil];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithUppercaseAuthenticateHeaderErrorPointerIsProvided_shouldReturnNilError
{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"WWW-AUTHENTICATE"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADAuthenticationError *error = nil;
    
    [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNil(error);
}

- (void)testParametersFromResponse_whenResponseWithUppercaseAuthenticateHeaderErrorPointerIsProvided_shouldReturnParametersWithAuthority
{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"WWW-AUTHENTICATE"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADAuthenticationError *error = nil;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNotNil(parameters.authority);
    ADAssertStringEquals(parameters.authority, @"https://www.example.com");
}

- (void)testParametersFromResponse_whenResponseWithPartiallyUppercaseAuthenticateHeaderErrorPointerIsProvided_shouldReturnNilError
{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"www-AUTHEnticate"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADAuthenticationError *error = nil;
    
    [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNil(error);
}

- (void)testParametersFromResponse_whenResponseWithPartiallyUppercaseAuthenticateHeaderErrorPointerIsProvided_shouldReturnParametersWithAuthority
{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"www-AUTHEnticate"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADAuthenticationError *error = nil;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNotNil(parameters.authority);
    ADAssertStringEquals(parameters.authority, @"https://www.example.com");
}

#pragma mark - parametersFromResponseAuthenticateHeader

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderNilErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderNilErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderNilErrorPointerNil_shouldReturnNilParameters
{
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:nil error:nil];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsValid_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"something.com\", anotherParam=\"Indeed, another param=5\" " error:&error];
    
    XCTAssertNil(error);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsValid_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"something.com\", anotherParam=\"Indeed, another param=5\" " error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(parameters.resource);
    ADAssertStringEquals(parameters.authority, @"https://login.windows.net/common");
    NSDictionary *extractedParameters = [parameters extractedParameters];
    XCTAssertNotNil(extractedParameters);
    ADAssertStringEquals([extractedParameters objectForKey:@"anotherParam"], @"Indeed, another param=5");
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsInvalid_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\".\\..\\windows\\system32\\drivers\\etc\\host\"" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsValid_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    ADAuthenticationParameters *parameters = [ADAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\".\\..\\windows\\system32\\drivers\\etc\\host\"" error:&error];
    
    XCTAssertNil(parameters);
}

#pragma mark - extractChallengeParameters

- (void)testExtractChallengeParameters_whenHeaderContentsNilErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:nil error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsNilErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:nil error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsEmptyErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsEmptyErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsBlankErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"   " error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsBlankErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"   " error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value:    ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerButIsInvalidErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"BearerBlahblah" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerButIsInvalidErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"BearerBlahblah" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: BearerBlahblah");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerCommaButIsInvalidErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer,, " error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerCommaButIsInvalidErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer,, " error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer,, ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceButIsInvalidErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer test string" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceButIsInvalidErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer test string" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer test string");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerauthorizationErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearerauthorization_uri=\"abc\", resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerauthorizationErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearerauthorization_uri=\"abc\", resource_id=\"something\"" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualBarErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualBarErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteErrorPointerIsProvided_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteErrorPointerIsProvided_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"something"], @"bar");
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    // Missing second quote.
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar" error:&error];
    
    XCTAssertNil(parameters);
}

-(void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteCommaErrorPointerIsProvided_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"," error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteCommaErrorPointerIsProvided_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"," error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerMultipleSpacesAuthorizationUriErrorPointerIsProvided_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer   authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerMultipleSpacesAuthorizationUriErrorPointerIsProvided_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer   authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUriErrorPointerIsProvided_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUriErrorPointerIsProvided_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUriCommaResourceIdErrorPointerIsProvided_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUriCommaResourceIdErrorPointerIsProvided_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasEmptyAuthorizationUriAndValidResourceIdErrorPointerIsProvided_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"\",resource_id=\"something\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasEmptyAuthorizationUriAndValidResourceIdErrorPointerIsProvided_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(parameters[@"authorization_uri"]);
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasCommasInAttribute_shouldReturnNilError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasCommasInAttribute_shouldReturnParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"error_descritpion"], @"Make sure, that you handle commas, inside the text");
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasAttributeValueWithoutQuotes_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasAttributeValueWithoutQuotes_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer something=bar");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidAndContainsEqualsCommasSpaces_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer = , = , " error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidAndContainsEqualsCommasSpaces_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer = , = , " error:&error];
    
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidAndContainsEqualsCommas_shouldReturnError
{
    ADAuthenticationError *error;
    
    [ADAuthenticationParameters extractChallengeParameters:@"Bearer =,=,=" error:&error];
    
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidandContainsEqualsCommasSpaces_shouldReturnNilParameters
{
    ADAuthenticationError *error;
    
    NSDictionary *parameters = [ADAuthenticationParameters extractChallengeParameters:@"Bearer =,=,=" error:&error];
    
    XCTAssertNil(parameters);
}

@end
