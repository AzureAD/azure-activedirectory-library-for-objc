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

#import "ADAL_Internal.h"
#import "ADLogger.h"
#import "NSString+ADHelperMethods.h"
#import "ADErrorCodes.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationSettings.h"
#import <libkern/OSAtomic.h>
#import <Foundation/NSObjCRuntime.h>
#import <objc/runtime.h>
#import "ADTestURLConnection.h"
#import "ADOAuth2Constants.h"
#import "ADTokenCacheKey.h"

@implementation XCTestCase (TestHelperMethods)

//Tracks the logged messages.
NSMutableString* sLogLevelsLog;
NSMutableString* sMessagesLog;
NSMutableString* sInformationLog;
NSMutableString* sErrorCodesLog;
ADAL_LOG_LEVEL sMaxAcceptedLogLevel;//If a message is logged above it, the test will fail.

NSString* const sTestBegin = @"|||TEST_BEGIN|||";
NSString* const sTestEnd = @"|||TEST_END|||";

NSString* const sIdTokenClaims = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224170,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\",\"altsecid\":\"Some Guest id\",\"idp\":\"Fake IDP\",\"email\":\"fake e-mail\"}";
NSString* const sIDTokenHeader = @"{\"typ\":\"JWT\",\"alg\":\"none\"}";

volatile int sAsyncExecuted;//The number of asynchronous callbacks executed.

/* See header for details. */
- (void)adValidateForInvalidArgument:(NSString *)argument
                               error:(ADAuthenticationError *)error
{
    XCTAssertNotNil(argument, "Internal test error: please specify the expected parameter.");
    
    
    XCTAssertNotNil(error, "Error should be raised for the invalid argument '%@'", argument);
    XCTAssertNotNil(error.domain, "Error domain is nil.");
    XCTAssertEqual(error.domain, ADInvalidArgumentDomain, "Incorrect error domain.");
    XCTAssertNil(error.protocolCode, "The protocol code should not be set. Instead protocolCode ='%@'.", error.protocolCode);
    XCTAssertFalse([NSString adIsStringNilOrBlank:error.errorDetails], @"Error should have details.");
    BOOL found = [error.errorDetails adContainsString:argument];
    XCTAssertTrue(found, "The parameter is not specified in the error details. Error details:%@", error.errorDetails);
}


/* See header for details.*/
- (void)adValidateFactoryForInvalidArgument:(NSString *)argument
                             returnedObject:(id)returnedObject
                                      error:(ADAuthenticationError *)error
{
    XCTAssertNil(returnedObject, "Creator should have returned nil. Object: %@", returnedObject);
    
    [self adValidateForInvalidArgument:argument error:error];
}

- (void)adSetLogTolerance:(ADAL_LOG_LEVEL)maxLogTolerance
{
    sMaxAcceptedLogLevel = maxLogTolerance;
}

/*! Sets logging and other infrastructure for a new test */
- (void)adTestBegin:(ADAL_LOG_LEVEL)maxLogTolerance;
{
    [self adSetLogTolerance:maxLogTolerance];
    
    @synchronized(self.class)
    {
        static dispatch_once_t once = 0;
        
        dispatch_once(&once, ^{
            sLogLevelsLog = [NSMutableString new];
            sMessagesLog = [NSMutableString new];
            sInformationLog = [NSMutableString new];
            sErrorCodesLog = [NSMutableString new];
        });
        
        //Note beginning of the test:
        [sLogLevelsLog appendString:sTestBegin];
        [sMessagesLog appendString:sTestBegin];
        [sInformationLog appendString:sTestBegin];
        [sErrorCodesLog appendString:sTestBegin];
    }
    
    LogCallback logCallback = ^(ADAL_LOG_LEVEL logLevel,
                                NSString* message,
                                NSString* additionalInformation,
                                NSInteger errorCode)
    {
        @synchronized(self.class)
        {
            //Write a single message:
            [sLogLevelsLog appendFormat:@"|%u|", logLevel];
            [sMessagesLog appendFormat:@"|%@|", message];
            [sInformationLog appendFormat:@"|%@|", additionalInformation];
            [sErrorCodesLog appendFormat:@"|%lu|", (long)errorCode];
            
            if (logLevel < sMaxAcceptedLogLevel)
            {
                NSString* fail = [NSString stringWithFormat:@"Level: %u; Message: %@; Info: %@; Code: %lu",
                                  logLevel, message, additionalInformation, (long)errorCode];
                
                [self recordFailureWithDescription:fail inFile:@"" __FILE__ atLine:__LINE__ expected:NO];
            }
        }
    };
    
    
    [ADLogger setLogCallBack:logCallback];
    [ADLogger setLevel:ADAL_LOG_LAST];//Log everything by default. Tests can change this.
    [ADLogger setNSLogging:NO];//Disables the NS logging to avoid generating huge amount of system logs.
    
    // ARC: comparing two block objects is not valid in non-ARC environments
    //XCTAssertEqual(logCallback, [ADLogger getLogCallBack], "Setting of logCallBack failed.");
}

/*! Clears logging and other infrastructure after a test */
- (void)adTestEnd
{
    [ADLogger setLogCallBack:nil];
    @synchronized(self.class)
    {
        //Write ending of the test:
        [sLogLevelsLog appendString:sTestEnd];
        [sMessagesLog appendString:sTestEnd];
        [sInformationLog appendString:sTestEnd];
        [sErrorCodesLog appendString:sTestEnd];
    }
    XCTAssertNil([ADLogger getLogCallBack], "Clearing of logCallBack failed.");
}

//Parses backwards the log to find the test begin prefix. Returns the beginning
//of the log string if not found:
- (long)indexOfTestBegin:(NSString *)log
{
    NSUInteger index = [log rangeOfString:sTestBegin options:NSBackwardsSearch].location;
    return (index == NSNotFound) ? 0 : index;
}

- (NSString *)adLogLevelLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sLogLevelsLog substringFromIndex:[self indexOfTestBegin:sLogLevelsLog]];
    }
    return toReturn;
}

- (NSString *)adMessagesLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sMessagesLog substringFromIndex:[self indexOfTestBegin:sMessagesLog]];
    }
    return toReturn;
}

- (NSString *)adInformationLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sInformationLog substringFromIndex:[self indexOfTestBegin:sInformationLog]];
    }
    return toReturn;
}

- (NSString *)adErrorCodesLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sErrorCodesLog substringFromIndex:[self indexOfTestBegin:sErrorCodesLog]];
    }
    return toReturn;
}

//Helper method to count how many times a string occurs in another string:
- (int)adCountOccurencesOf:(NSString *)contained
                  inString:(NSString *)string
{
    XCTAssertNotNil(contained);
    XCTAssertNotNil(string);
    
    NSRange range = {.location = 0, .length = string.length};
    int occurences = 0;
    long end = string.length - contained.length;
    while (range.location < end)
    {
        NSRange result = [string rangeOfString:contained options:NSLiteralSearch range:range];
        if (result.location != NSNotFound)
        {
            ++occurences;
            range.location = result.location + result.length;
            range.length = string.length - range.location;
        }
        else
        {
            break;
        }
    }
    return occurences;
}

//The methods help with verifying of the logs:
- (int)adCountOfLogOccurrencesIn:(ADLogPart)logPart
                        ofString:(NSString *)contained
{
    NSString* log = [self adGetLogs:logPart];
    return [self adCountOccurencesOf:contained inString:log];
}

//String clearing helper method:
- (void)clearString:(NSMutableString *)string
{
    NSRange all = {.location = 0, .length = string.length};
    [string deleteCharactersInRange:all];
}

- (void)adClearLogs
{
    @synchronized(self.class)
    {
        [self clearString:sLogLevelsLog];
        [self clearString:sMessagesLog];
        [self clearString:sInformationLog];
        [self clearString:sErrorCodesLog];
    }
}

- (NSString *)adGetLogs:(ADLogPart)logPart
{
    switch (logPart) {
        case TEST_LOG_LEVEL:
            return [self adLogLevelLogs];
        case TEST_LOG_MESSAGE:
            return [self adMessagesLogs];
        case TEST_LOG_INFO:
            return [self adInformationLogs];
        case TEST_LOG_CODE:
            return [self adErrorCodesLogs];
            
        default:
            XCTFail("Unknown ADLogPart: %u", logPart);
            return @"";
    }
}

- (void)adAssertLogsContain:(NSString *)text
                    logPart:(ADLogPart)logPart
                       file:(const char *)file
                       line:(int)line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if (![logs adContainsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test do not contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

- (void)adAssertLogsDoNotContain:(NSString *)text
                         logPart:(ADLogPart)logPart
                            file:(const char *)file
                            line:(int)line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if ([logs adContainsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

- (void)adAssertStringEquals:(NSString *)actual
            stringExpression:(NSString *)expression
                    expected:(NSString *)expected
                        file:(const char *)file
                        line:(int)line
{
    if (!actual && !expected)//Both nil, so they are equal
        return;
    if (![expected isEqualToString:actual])
    {
        _XCTFailureHandler(self, YES, file, line, @"Strings.", @"" "The strings are different: '%@' = '%@', expected '%@'", expression, actual, expected);
    }
}

- (ADTokenCacheItem *)adCreateCacheItem
{
    return [self adCreateCacheItem:TEST_USER_ID];
}

//Creates an new item with all of the properties having correct
//values
- (ADTokenCacheItem *)adCreateCacheItem:(NSString *)userId
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = TEST_REFRESH_TOKEN;
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    if (![NSString adIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId];
    }
    item.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    
    return item;
}

- (ADTokenCacheItem *)adCreateATCacheItem
{
    return [self adCreateATCacheItem:TEST_RESOURCE userId:TEST_USER_ID];
}

- (ADTokenCacheItem *)adCreateATCacheItem:(NSString *)resource
                                   userId:(NSString *)userId
{
    
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = resource;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = nil;
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    if (![NSString adIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId];
    }
    item.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    
    return item;
}

- (ADTokenCacheItem *)adCreateMRRTCacheItem
{
    return [self adCreateMRRTCacheItem:TEST_USER_ID];
}

- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
{
    // A MRRT item is just a refresh token, it doesn't have a specified resource
    // an expiration time (that we know about) and covers multiple ATs.
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.refreshToken = TEST_REFRESH_TOKEN;
    if (![NSString adIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId];
    }
    
    return item;
}

- (ADTokenCacheKey *)adCreateCacheKey
{
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                              resource:TEST_RESOURCE
                                                              clientId:TEST_CLIENT_ID
                                                                 error:nil];
    
    return key;
}

- (ADUserInformation *)adCreateUserInformation:(NSString*)userId
{
    NSAssert(userId, @"userId cannot be nil!");
    NSDictionary* part1_claims = @{ @"typ" : @"JWT",
                                    @"alg" : @"none" };
    
    NSDictionary* idtoken_claims = @{ @"aud" : @"c3c7f5e5-7153-44d4-90e6-329686d48d76",
                                      @"iss" : @"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                      @"iat" : @"1387224169",
                                      @"nbf" : @"1387224169",
                                      @"exp" : @"1387227769",
                                      @"ver" : @"1.0",
                                      @"tid" : @"6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                      @"oid" : @"53c6acf2-2742-4538-918d-e78257ec8516",
                                      @"upn" : userId,
                                      @"unique_name" : userId,
                                      @"sub" : @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc",
                                      @"family_name" : @"Cartman",
                                      @"given_name" : @"Eric"
                                      };
    
    NSString* idtoken = [NSString stringWithFormat:@"%@.%@",
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:part1_claims options:0 error:nil]],
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_claims options:0 error:nil]]];
    
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:idtoken error:nil];
    
    // If you're hitting this you might as well fix it before trying to run other tests.
    NSAssert(userInfo, @"Failed to create a userinfo object from a static idtoken. Something must have horribly broke,");
    return userInfo;
}

- (void)adCallAndWaitWithFile:(NSString *)file
                         line:(int)line
                    semaphore:(dispatch_semaphore_t)sem
                        block:(void (^)(void))block
{
    THROW_ON_NIL_ARGUMENT(sem);
    THROW_ON_NIL_EMPTY_ARGUMENT(file);
    THROW_ON_NIL_ARGUMENT(block);
    
    (void)line;
    
    block();//Run the intended asynchronous method
    while (dispatch_semaphore_wait(sem, DISPATCH_TIME_NOW))
    {
        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
}

- (ADTestURLResponse *)adResponseBadRefreshToken:(NSString *)refreshToken
                                       authority:(NSString *)authority
                                        resource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                   correlationId:(NSUUID *)correlationId
{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, authority];
    
    NSDictionary* headers = nil;
    if (correlationId)
    {
        headers = @{ OAUTH2_CORRELATION_ID_REQUEST_VALUE : [correlationId UUIDString] };
    }
    
    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:headers
                      requestParamsBody:@{ OAUTH2_GRANT_TYPE : @"refresh_token",
                                           OAUTH2_REFRESH_TOKEN : refreshToken,
                                           OAUTH2_RESOURCE : resource,
                                           OAUTH2_CLIENT_ID : clientId }
                      responseURLString:@"https://contoso.com"
                           responseCode:400
                       httpHeaderFields:@{}
                       dictionaryAsJSON:@{ OAUTH2_ERROR : @"bad_refresh_token",
                                           OAUTH2_ERROR_DESCRIPTION : @"oauth error description"}];
    
    return response;
}

- (ADTestURLResponse *)adDefaultBadRefreshTokenResponse
{
    return [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                                 authority:TEST_AUTHORITY
                                  resource:TEST_RESOURCE
                                  clientId:TEST_CLIENT_ID
                             correlationId:TEST_CORRELATION_ID];
}

- (ADTestURLResponse *)adDefaultRefreshResponse:(NSString *)newRefreshToken
                                    accessToken:(NSString *)newAccessToken
{
    return [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                              authority:TEST_AUTHORITY
                               resource:TEST_RESOURCE
                               clientId:TEST_CLIENT_ID
                          correlationId:TEST_CORRELATION_ID
                        newRefreshToken:newRefreshToken
                         newAccessToken:newAccessToken];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, authority];
    
    NSDictionary* headers = nil;
    if (correlationId)
    {
        headers = @{ OAUTH2_CORRELATION_ID_REQUEST_VALUE : [correlationId UUIDString] };
    }
    
    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:headers
                      requestParamsBody:@{ OAUTH2_GRANT_TYPE : @"refresh_token",
                                           OAUTH2_REFRESH_TOKEN : oldRefreshToken,
                                           OAUTH2_RESOURCE : resource,
                                           OAUTH2_CLIENT_ID : clientId }
                      responseURLString:@"https://contoso.com"
                           responseCode:400
                       httpHeaderFields:@{}
                       dictionaryAsJSON:@{ OAUTH2_REFRESH_TOKEN : newRefreshToken,
                                           OAUTH2_ACCESS_TOKEN : newAccessToken,
                                           OAUTH2_RESOURCE : resource }];
    
    return response;

}

@end
