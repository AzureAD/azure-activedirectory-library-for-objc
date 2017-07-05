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
#import "ADAuthenticationError.h"
#import "ADAL_Internal.h"
#import "ADTelemetry.h"

#define ADTAssertContains(_str, _contains) XCTAssertTrue([_str containsString:_contains], "%@ does not contain \"%@\"", _str, _contains)

#define TEST_AUTHORITY @"https://login.windows.net/contoso.com"
#define TEST_REDIRECT_URL [NSURL URLWithString:@"urn:ietf:wg:oauth:2.0:oob"]
#define TEST_RESOURCE @"resource"
#define TEST_USER_ID @"eric_cartman@contoso.com"
#define TEST_CLIENT_ID @"c3c7f5e5-7153-44d4-90e6-329686d48d76"
#define TEST_ACCESS_TOKEN @"access token"
#define TEST_ACCESS_TOKEN_TYPE @"access token type"
#define TEST_REFRESH_TOKEN @"refresh token"
#define TEST_CORRELATION_ID ({NSUUID *testID = [[NSUUID alloc] initWithUUIDString:@"6fd1f5cd-a94c-4335-889b-6c598e6d8048"]; testID;})

#define TEST_SIGNAL dispatch_semaphore_signal(_dsem)
#define TEST_WAIT dispatch_semaphore_wait(_dsem, DISPATCH_TIME_FOREVER)
#define TEST_WAIT_NOT_BLOCKING_MAIN_QUEUE \
{ \
    while (dispatch_semaphore_wait(_dsem, DISPATCH_TIME_NOW)) \
    { \
        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate: [NSDate distantFuture]]; \
    } \
} \

typedef enum
{
    TEST_LOG_LEVEL,
    TEST_LOG_MESSAGE,
    TEST_LOG_INFO,
    TEST_LOG_CODE,
} ADLogPart;

@class ADTokenCacheItem;
@class ADUserInformation;
@class ADTokenCacheKey;
@class ADTestURLResponse;

@interface XCTestCase (HelperMethods)

- (void)adAssertStringEquals:(NSString *)actual
            stringExpression:(NSString *)expression
                    expected:(NSString *)expected
                        file:(const char *)file
                        line:(int)line;

/*! Used with the class factory methods that create class objects. Verifies
 the expectations when the passed argument is invalid:
 - The creator should return nil.
 - The error should be set accordingly, containing the argument in the description.*/
- (void)adValidateFactoryForInvalidArgument:(NSString *)argument
                             returnedObject:(id)returnedObject
                                      error:(ADAuthenticationError *)error;

- (ADTestURLResponse *)adResponseBadRefreshToken:(NSString *)refreshToken
                                       authority:(NSString *)authority
                                        resource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                      oauthError:(NSString *)oauthError
                                   correlationId:(NSUUID *)correlationId;
- (ADTestURLResponse *)adDefaultBadRefreshTokenResponseError:(NSString*)oauthError;
- (ADTestURLResponse *)adDefaultBadRefreshTokenResponse;

- (ADTestURLResponse *)adDefaultRefreshResponse:(NSString *)newRefreshToken
                                    accessToken:(NSString *)newAccessToken;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken;

/*! Used for constructing a refresh token response with additional information in the JSON body */
- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields;


- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields;

/*! Used for constructing a response with the provided refresh token parameters */
- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                                 responseCode:(NSInteger)responseCode
                              responseHeaders:(NSDictionary *)responseHeaders
                                 responseJson:(NSDictionary *)responseJson;


- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                                 responseCode:(NSInteger)responseCode
                              responseHeaders:(NSDictionary *)responseHeaders
                                 responseJson:(NSDictionary *)responseJson;

/*! Used for constructing a response with a specific HTTP code and HTTP headers 
    to a default refresh token request */
- (ADTestURLResponse *)adDefaultRefreshReponseCode:(NSInteger)responseCode
                                   responseHeaders:(NSDictionary *)responseHeaders
                                      responseJson:(NSDictionary *)responseJson;

/*! Verifies that the correct error is returned when any method was passed invalid arguments.
 */
- (void)adValidateForInvalidArgument:(NSString *)argument
                               error:(ADAuthenticationError *)error;

/*! Sets logging and other infrastructure for a new test.
 The method sets the callback and fails the tests if a the logs contains higher level
 item than the maxLogTolerance. E.g. strict test may set this parameter to ADAL_LOG_LEVEL_INFO,
 so that all warnings and errors will be cause the test to fail.*/
- (void)adTestBegin:(ADAL_LOG_LEVEL)maxLogTolerance;

/*! See description of adTestBegin. */
- (void)adSetLogTolerance: (ADAL_LOG_LEVEL)maxLogTolerance;

/*! Clears logging and other infrastructure after a test */
- (void)adTestEnd;

//Creates a new item with all of the properties having correct values
- (ADTokenCacheItem *)adCreateCacheItem;
- (ADTokenCacheItem *)adCreateCacheItem:(NSString*)userId;
- (ADTokenCacheItem *)adCreateATCacheItem;
- (ADTokenCacheItem *)adCreateATCacheItem:(NSString *)resource
                                   userId:(NSString *)userId;
- (ADTokenCacheItem *)adCreateMRRTCacheItem;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
                                   familyId:(NSString *)familyId;
- (ADTokenCacheItem *)adCreateFRTCacheItem;
- (ADTokenCacheItem *)adCreateFRTCacheItem:(NSString *)familyId
                                    userId:(NSString *)userId;
- (ADTokenCacheKey *)adCreateCacheKey;

//Creates a sample user information object
- (ADUserInformation *)adCreateUserInformation:(NSString*)userId;

- (NSString *)adLogLevelLogs;
- (NSString *)adMessagesLogs;
- (NSString *)adInformationLogs;
- (NSString *)adErrorCodesLogs;

//Counts how many times the "contained" is sequentially occurring in "string".
//Example: "bar bar" is contained once in "bar bar bar" and twice in "bar bar bar bar".
- (int)adCountOccurencesOf:(NSString *)contained
                  inString:(NSString *)string;

//The methods help with verifying of the logs:
- (int)adCountOfLogOccurrencesIn:(ADLogPart)logPart
                        ofString:(NSString *)contained;

//Checks if the test coverage is enabled and stores the test coverage, if yes.
- (void)adFlushCodeCoverage;

/* A special helper, which invokes the 'block' parameter in the UI thread and waits for its internal
 callback block to complete.
 IMPORTANT: The internal callback block should end with ASYNCH_COMPLETE macro to signal its completion. Example:
 static volatile int comletion  = 0;
 [self adCallAndWaitWithFile:@"" __FILE__ line:__LINE__ completionSignal: &completion block:^
 {
    [mAuthenticationContext acquireTokenWithResource:mResource
                                     completionBlock:^(ADAuthenticationResult* result)
    {
        //Inner block:
        mResult = result;
        ASYNC_BLOCK_COMPLETE(completion);//Signals the completion
    }];
 }];
 The method executes the block in the UI thread, but runs an internal run loop and thus allows methods which enqueue their
 completion callbacks on the UI thread.
 */
- (void)adCallAndWaitWithFile:(NSString*)file
                         line:(int)line
                    semaphore:(dispatch_semaphore_t)signal
                        block:(void (^)(void)) block;

@end

//Fixes the issue with XCTAssertEqual not comparing int and long values
//Usage: ADAssertLongEquals(5, [self calculateFive]);
#define ADAssertLongEquals(CONST, EXPR) XCTAssertEqual((long)CONST, (long)EXPR)

#define ADAssertThrowsArgument(EXP) \
{ \
    XCTAssertThrowsSpecificNamed((EXP), NSException, NSInvalidArgumentException, "Exception expected for %s", #EXP); \
}

//Usage: ADAssertStringEquals(resultString, "Blah");
#define ADAssertStringEquals(actualParam, expectedParam) \
{ \
    [self adAssertStringEquals:actualParam \
              stringExpression:@"" #actualParam \
                      expected:expectedParam \
                           file:__FILE__ \
                           line:__LINE__]; \
}

//Fixes the problem with the test framework not able to compare dates:
#define ADAssertDateEquals(actualParam, expectedParam) XCTAssertTrue([expectedParam compare:actualParam] == NSOrderedSame)


//Verifes that "error" local variable is nil. If not prints the error
#define ADAssertNoError XCTAssertNil(error, "Unexpected error occurred: %@", error.errorDetails)

