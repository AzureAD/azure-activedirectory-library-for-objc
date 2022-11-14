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
#import "ADALAuthenticationParameters.h"
#import "ADALAuthenticationSettings.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADALAuthenticationParameters+Internal.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"

@interface ADALAuthenticationParametersTests : ADTestCase

@end

@implementation ADALAuthenticationParametersTests

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
    XCTAssertThrows([ADALAuthenticationParameters new], "Creation with new should throw.");
}

- (void)testInit_shouldThrow
{
    XCTAssertThrows([[ADALAuthenticationParameters alloc] init], "Default init method should throw.");
}

#pragma mark - parametersFromResourceUrl

- (void)testParametersFromResourceUrl_whenResourceUrlIsNil_shouldReturnErrorAndNilParameters
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with nil resource should return error."];
    
    NSURL *resource = nil;
    [ADALAuthenticationParameters parametersFromResourceUrl:resource completionBlock:^(ADALAuthenticationParameters *parameters, ADALAuthenticationError *error)
     {
         XCTAssertNotNil(error);
         ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
         XCTAssertNil(error.protocolCode);
         ADAssertStringEquals(error.errorDetails, @"The argument 'resourceUrl' is invalid. Value:(null)");
         XCTAssertNil(parameters);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenCompletionBlockIsNil_shouldThrowException
{
    NSURL *resource = [[NSURL alloc] initWithString:@"https://mytodolist.com"];
    
    ADParametersCompletion completion = nil;
    XCTAssertThrowsSpecificNamed([ADALAuthenticationParameters parametersFromResourceUrl:resource completionBlock:completion], NSException, NSInvalidArgumentException);
}

- (void)testParametersFromResourceUrl_whenResourceUrlIsNotExist_shouldReturnErrorAndNilParameters
{
    NSURL *resource = [[NSURL alloc] initWithString:@"https://noneistingurl12345676789.com"];
    [ADTestURLSession addNotFoundResponseForURLString:@"https://noneistingurl12345676789.com"];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"parametersFromResourceUrl: with non existing resource should return error."];
    [ADALAuthenticationParameters parametersFromResourceUrl:resource completionBlock:^(ADALAuthenticationParameters *parameters, ADALAuthenticationError __unused *error)
     {
         XCTAssertNotNil(error);
         XCTAssertFalse([NSString msidIsStringNilOrBlank:error.errorDetails], @"Error should have details.");
         XCTAssertNil(parameters);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpResourceUrlExists_shouldReturnAuthenticationParametersAndNilError
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"http://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"http://testapi007.azurewebsites.net/api/WorkItem"
                                                    responseURLString:@"http://contoso.com"
                                                         responseCode:ADAL_HTTP_UNAUTHORIZED
                                                     httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                                     dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADALAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADALAuthenticationParameters *parameters, ADALAuthenticationError __unused *error)
     {
         XCTAssertNotNil(parameters);
         XCTAssertNotNil(parameters.authority);
         XCTAssertEqualObjects(parameters.authority, @"https://login.windows.net/omercantest.onmicrosoft.com");
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testParametersFromResourceUrl_whenHttpsResourceUrlExists_shouldReturnAuthenticationParametersAndNilError
{
    NSURL *resourceUrl = [[NSURL alloc] initWithString:@"https://testapi007.azurewebsites.net/api/WorkItem"];
    ADTestURLResponse *response = [ADTestURLResponse requestURLString:@"https://testapi007.azurewebsites.net/api/WorkItem"
                                 responseURLString:@"https://contoso.com"
                                      responseCode:ADAL_HTTP_UNAUTHORIZED
                                  httpHeaderFields:@{@"WWW-Authenticate" : @"Bearer authorization_uri=\"https://login.windows.net/omercantest.onmicrosoft.com\"" }
                                  dictionaryAsJSON:@{}];
    [ADTestURLSession addResponse:response];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get parameters for valid resourceUrl."];
    
    [ADALAuthenticationParameters parametersFromResourceUrl:resourceUrl completionBlock:^(ADALAuthenticationParameters *parameters, ADALAuthenticationError __unused *error)
     {
         XCTAssertNotNil(parameters);
         XCTAssertNotNil(parameters.authority);
         XCTAssertEqualObjects(parameters.authority, @"https://login.windows.net/omercantest.onmicrosoft.com");
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

#pragma mark - parametersFromResponse

- (void)testParametersFromResponse_whenResponseNilErrorPointerIsProvided_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSHTTPURLResponse *response = nil;
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:&error];

    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The argument 'response' is invalid. Value:(null)");
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseNilErrorPointerNil_shouldReturnNilParameters
{
    NSHTTPURLResponse *response = nil;
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:nil];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithoutAuthenticateHeaderErrorPointerIsProvided_shouldReturnErrorAndNilParameters
{
    NSHTTPURLResponse *response = [NSHTTPURLResponse new];
    ADALAuthenticationError *error;
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' is missing in the Unauthorized (401) response. Make sure that the resouce server supports OAuth2 protocol.");
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithoutAuthenticateHeaderErrorPointerNil_shouldReturnNilParameters
{
    NSHTTPURLResponse *response = [NSHTTPURLResponse new];
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:nil];
    
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponse_whenResponseWithUppercaseAuthenticateHeader_shouldReturnParametersAndNilError
{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"WWW-AUTHENTICATE"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADALAuthenticationError *error = nil;
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNotNil(parameters.authority);
    ADAssertStringEquals(parameters.authority, @"https://www.example.com");
    XCTAssertNil(error);
}

- (void)testParametersFromResponse_whenResponseWithPartiallyUppercaseAuthenticateHeader_shouldReturnParametersAndNilError

{
    NSURL *url = [NSURL URLWithString:@"http://www.example.com"];
    NSDictionary *headerFields = [NSDictionary dictionaryWithObject:@"Bearer authorization_uri=\"https://www.example.com\""
                                                             forKey:@"www-AUTHEnticate"];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url
                                                              statusCode:401
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    ADALAuthenticationError *error = nil;
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponse:response error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNotNil(parameters.authority);
    ADAssertStringEquals(parameters.authority, @"https://www.example.com");
    XCTAssertNil(error);
}

#pragma mark - parametersFromResponseAuthenticateHeader

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderNil_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSString *authHeader = nil;
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponseAuthenticateHeader:authHeader error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsValid_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\"https://login.windows.net/common\", resource_uri=\"something.com\", anotherParam=\"Indeed, another param=5\" " error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(parameters.resource);
    ADAssertStringEquals(parameters.authority, @"https://login.windows.net/common");
    NSDictionary *extractedParameters = [parameters extractedParameters];
    XCTAssertNotNil(extractedParameters);
    ADAssertStringEquals([extractedParameters objectForKey:@"anotherParam"], @"Indeed, another param=5");
    XCTAssertNil(error);
}

- (void)testParametersFromResponseAuthenticateHeader_whenHeaderIsInvalid_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    ADALAuthenticationParameters *parameters = [ADALAuthenticationParameters parametersFromResponseAuthenticateHeader:@"Bearer authorization_uri=\".\\..\\windows\\system32\\drivers\\etc\\host\"" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

#pragma mark - extractChallengeParameters

- (void)testExtractChallengeParameters_whenHeaderContentsNil_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsEmpty_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsBlank_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"   " error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value:    ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerButIsInvalid_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"BearerBlahblah" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: BearerBlahblah");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerCommaButIsInvalid_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer,, " error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer,, ");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceButIsInvalid_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer test string" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer test string");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerauthorization_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearerauthorization_uri=\"abc\", resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomething_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualBar_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuote_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"something"], @"bar");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBar_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    // Missing second quote.
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

-(void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteComma_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\"," error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

-(void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceSomethingEqualQuoteBarQuoteCommaSpace_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=\"bar\", " error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerMultipleSpacesAuthorizationUri_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer   authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUri_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsStartsWithBearerSpaceAuthorizationUriCommaResourceId_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasEmptyAuthorizationUriAndValidResourceId_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer authorization_uri=\"\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(parameters[@"authorization_uri"]);
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasCommasInAttribute_shouldReturnParametersAndNilError
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer  error_descritpion=\"Make sure, that you handle commas, inside the text\",authorization_uri=\"https://login.windows.net/common\",resource_id=\"something\"" error:&error];
    
    XCTAssertNotNil(parameters);
    ADAssertStringEquals(parameters[@"error_descritpion"], @"Make sure, that you handle commas, inside the text");
    ADAssertStringEquals(parameters[@"authorization_uri"], @"https://login.windows.net/common");
    ADAssertStringEquals(parameters[@"resource_id"], @"something");
    XCTAssertNil(error);
}

- (void)testExtractChallengeParameters_whenHeaderContentsHasAttributeValueWithoutQuotes_shouldReturnErrorANdNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer something=bar" error:&error];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The authentication header 'WWW-Authenticate' for the Unauthorized (401) response cannot be parsed. Header value: Bearer something=bar");
    XCTAssertEqual(error.code, AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidAndContainsEqualsCommasSpaces_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer = , = , " error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenHeaderContentsIsInvalidAndContainsEqualsCommas_shouldReturnErrorAndNilParameters
{
    ADALAuthenticationError *error;
    
    NSDictionary *parameters = [ADALAuthenticationParameters extractChallengeParameters:@"Bearer =,=,=" error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertNil(parameters);
}

- (void)testExtractChallengeParameters_whenMultipleChallengesBearerFirst_shouldReturnParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Bearer authorization_uri=\"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47\", Basic realm=\"https://contoso.com/\", TFS-Federated";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(error);
    XCTAssertEqualObjects(parameters, @{ @"authorization_uri" : @"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47" });
}

- (void)testExtractChallengeParameters_whenMultipleChallengesBearerLast_shouldReturnParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Badger realm=\"https://contoso.com/\", Bearer authorization_uri=\"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47\"";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(error);
    XCTAssertEqualObjects(parameters, @{ @"authorization_uri" : @"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47" });
}

- (void)testExtractChallengeParameters_whenMultipleChallengesWithExtraWhitespaces_shouldReturnParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Badger realm=\"https://contoso.com/\", Bearer authorization_uri  =   \"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47\"";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(error);
    XCTAssertEqualObjects(parameters, @{ @"authorization_uri" : @"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47" });
}

- (void)testExtractChallengeParameters_whenMultipleChallengesBearerAsParam_shouldReturnParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Badger Bearer =\"https://contoso.com/\", Bearer authorization_uri=\"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47\"";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNotNil(parameters);
    XCTAssertNil(error);
    XCTAssertEqualObjects(parameters, @{ @"authorization_uri" : @"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47" });
}

- (void)testExtractChallengeParameters_whenMultipleBearerChallendges_shouldReturnErrorAndNilParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Basic realm=\"https://contoso.com/\", Bearer authorization_uri=\"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47\", TFS-Federated, Bearer something=\"bar\"";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNil(parameters);
    XCTAssertNotNil(error);
}

- (void)testExtractChallengeParameters_whenBearerWithoutParameters_shouldReturnErrorAndNilParameters
{
    NSDictionary *parameters = nil;
    ADALAuthenticationError *error = nil;
    NSString *challengeString = @"Basic realm=\"https://contoso.com/\", Bearer, TFS-Federated";
    
    parameters = [ADALAuthenticationParameters extractChallengeParameters:challengeString
                                                                  error:&error];
    
    XCTAssertNil(parameters);
    XCTAssertNotNil(error);
}

@end
