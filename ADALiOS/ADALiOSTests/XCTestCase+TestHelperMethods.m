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

#import "XCTestCase+TestHelperMethods.h"
#import "../ADALiOS/ADAuthenticationContext.h"
#import "../ADALioS/ADAuthenticationSettings.h"
#import <libkern/OSAtomic.h>
#import <Foundation/NSObjCRuntime.h>
#import <objc/runtime.h>


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

/*! See header for comments */
-(void) adAssertValidText: (NSString*) text
                message: (NSString*) message
{
    //The pragmas here are copied directly from the XCTAssertNotNil:
    _Pragma("clang diagnostic push")
    _Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"")//Temporarily remove the compiler warning
    if ([NSString adIsStringNilOrBlank:text])
    {
        _XCTFailureHandler(self, YES, __FILE__, __LINE__, text, message);
    }
    _Pragma("clang diagnostic pop")//Restore the compiler warning
}

/* See header for details. */
-(void) adValidateForInvalidArgument: (NSString*) argument
                             error: (ADAuthenticationError*) error
{
    XCTAssertNotNil(argument, "Internal test error: please specify the expected parameter.");
    
    
    XCTAssertNotNil(error, "Error should be raised for the invalid argument '%@'", argument);
    XCTAssertNotNil(error.domain, "Error domain is nil.");
    XCTAssertEqual(error.domain, ADInvalidArgumentDomain, "Incorrect error domain.");
    XCTAssertNil(error.protocolCode, "The protocol code should not be set. Instead protocolCode ='%@'.", error.protocolCode);
    
    [self adAssertValidText:error.errorDetails message:@"The error should have details."];
    NSString* argumentString = [NSString stringWithFormat:@"'%@'", argument];
    BOOL found = [error.errorDetails adContainsString:argumentString];
    XCTAssertTrue(found, "The parameter is not specified in the error details. Error details:%@", error.errorDetails);
}


/* See header for details.*/
-(void) adValidateFactoryForInvalidArgument: (NSString*) argument
                           returnedObject: (id) returnedObject
                                    error: (ADAuthenticationError*) error
{
    XCTAssertNil(returnedObject, "Creator should have returned nil. Object: %@", returnedObject);
    
    [self adValidateForInvalidArgument:argument error:error];
}

-(void) adSetLogTolerance: (ADAL_LOG_LEVEL) maxLogTolerance
{
    sMaxAcceptedLogLevel = maxLogTolerance;
}

/*! Sets logging and other infrastructure for a new test */
-(void) adTestBegin: (ADAL_LOG_LEVEL) maxLogTolerance;
{
    [self adSetLogTolerance:maxLogTolerance];
    
    @synchronized(self.class)
    {
        static dispatch_once_t once;

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

    __block __weak  XCTestCase* weakSelf = self;
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
                [weakSelf recordFailureWithDescription:fail inFile:@"" __FILE__ atLine:__LINE__ expected:NO];
            }
        }
    };

    
    [ADLogger setLogCallBack:logCallback];
    [ADLogger setLevel:ADAL_LOG_LAST];//Log everything by default. Tests can change this.
    [ADLogger setNSLogging:NO];//Disables the NS logging to avoid generating huge amount of system logs.
    XCTAssertEqual(logCallback, [ADLogger getLogCallBack], "Setting of logCallBack failed.");
}

#ifdef AD_CODE_COVERAGE
extern void __gcov_flush(void);
#endif
-(void) adFlushCodeCoverage
{
#ifdef AD_CODE_COVERAGE
    __gcov_flush();
#endif
}

/*! Clears logging and other infrastructure after a test */
-(void) adTestEnd
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
    [self adFlushCodeCoverage];
}

//Parses backwards the log to find the test begin prefix. Returns the beginning
//of the log string if not found:
-(long) indexOfTestBegin: (NSString*) log
{
    NSUInteger index = [log rangeOfString:sTestBegin options:NSBackwardsSearch].location;
    return (index == NSNotFound) ? 0 : index;
}

-(NSString*) adLogLevelLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sLogLevelsLog substringFromIndex:[self indexOfTestBegin:sLogLevelsLog]];
    }
    return toReturn;
}

-(NSString*) adMessagesLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sMessagesLog substringFromIndex:[self indexOfTestBegin:sMessagesLog]];
    }
    return toReturn;
}

-(NSString*) adInformationLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sInformationLog substringFromIndex:[self indexOfTestBegin:sInformationLog]];
    }
    return toReturn;
}

-(NSString*) adErrorCodesLogs
{
    NSString* toReturn;
    @synchronized(self.class)
    {
        toReturn = [sErrorCodesLog substringFromIndex:[self indexOfTestBegin:sErrorCodesLog]];
    }
    return toReturn;
}

//Helper method to count how many times a string occurs in another string:
-(int) adCountOccurencesOf: (NSString*) contained
                  inString: (NSString*) string
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
-(int) adCountOfLogOccurrencesIn: (ADLogPart) logPart
                        ofString: (NSString*) contained
{
    NSString* log = [self adGetLogs:logPart];
    return [self adCountOccurencesOf:contained inString:log];
}

//String clearing helper method:
-(void) clearString: (NSMutableString*) string
{
    NSRange all = {.location = 0, .length = string.length};
    [string deleteCharactersInRange:all];
}

-(void) adClearLogs
{
    @synchronized(self.class)
    {
        [self clearString:sLogLevelsLog];
        [self clearString:sMessagesLog];
        [self clearString:sInformationLog];
        [self clearString:sErrorCodesLog];
    }
}

-(NSString*) adGetLogs: (ADLogPart) logPart
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

-(void) adAssertLogsContain: (NSString*) text
                    logPart: (ADLogPart) logPart
                       file: (const char*) file
                       line: (int) line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if (![logs adContainsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test do not contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

-(void) adAssertLogsDoNotContain: (NSString*) text
                         logPart: (ADLogPart) logPart
                            file: (const char*) file
                            line: (int) line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if ([logs adContainsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

-(void) adAssertStringEquals: (NSString*) actual
            stringExpression: (NSString*) expression
                    expected: (NSString*) expected
                        file: (const char*) file
                        line: (int) line
{
    if (!actual && !expected)//Both nil, so they are equal
        return;
    if (![expected isEqualToString:actual])
    {
        _XCTFailureHandler(self, YES, file, line, @"Strings.", @"" "The strings are different: '%@' = '%@', expected '%@'", expression, actual, expected);
    }
}

//Creates an new item with all of the properties having correct
//values
-(ADTokenCacheStoreItem*) adCreateCacheItem
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net/sometenant.com";
    item.clientId = @"client id";
    item.accessToken = @"access token";
    item.refreshToken = @"refresh token";
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    item.userInformation = [self adCreateUserInformation];
    item.accessTokenType = @"access token type";
    
    [self adVerifyPropertiesAreSet:item];
    
    return item;
}

-(ADUserInformation*) adCreateUserInformation
{
    ADAuthenticationError* error;
    //This one sets the "userId" property:
    NSString* id_token = [NSString stringWithFormat:@"%@.%@.",
                          [sIDTokenHeader adBase64UrlEncode],
                          [sIdTokenClaims adBase64UrlEncode]];
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:id_token error:&error];
    ADAssertNoError;
    XCTAssertNotNil(userInfo, "Nil user info returned.");

    //Check the standard properties:
    ADAssertStringEquals(userInfo.userId, @"boris@msopentechbv.onmicrosoft.com");
    ADAssertStringEquals(userInfo.givenName, @"Boriss");
    ADAssertStringEquals(userInfo.familyName, @"Vidolovv");
    ADAssertStringEquals(userInfo.subject, @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc");
    ADAssertStringEquals(userInfo.tenantId, @"6fd1f5cd-a94c-4335-889b-6c598e6d8048");
    ADAssertStringEquals(userInfo.upn, @"boris@MSOpenTechBV.onmicrosoft.com");
    ADAssertStringEquals(userInfo.uniqueName, @"boris@MSOpenTechBV.onmicrosoft.com");
    ADAssertStringEquals(userInfo.eMail, @"fake e-mail");
    ADAssertStringEquals(userInfo.identityProvider, @"Fake IDP");
    ADAssertStringEquals(userInfo.userObjectId, @"53c6acf2-2742-4538-918d-e78257ec8516");
    ADAssertStringEquals(userInfo.guestId, @"Some Guest id");
    
    //Check unmapped claims:
    ADAssertStringEquals([userInfo.allClaims objectForKey:@"aud"], @"c3c7f5e5-7153-44d4-90e6-329686d48d76");
    ADAssertStringEquals([userInfo.allClaims objectForKey:@"iss"], @"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/");
    XCTAssertEqualObjects([userInfo.allClaims objectForKey:@"iat"], [NSNumber numberWithLong:1387224169]);
    XCTAssertEqualObjects([userInfo.allClaims objectForKey:@"nbf"], [NSNumber numberWithLong:1387224170]);
    XCTAssertEqualObjects([userInfo.allClaims objectForKey:@"exp"], [NSNumber numberWithLong:1387227769]);
    ADAssertStringEquals([userInfo.allClaims objectForKey:@"ver"], @"1.0");
    
    //This will check absolutely all properties, so that if we add a new one later
    //it will fail if it is not set:
    [self adVerifyPropertiesAreSet:userInfo];
    
    return userInfo;
}

-(void) adVerifyPropertiesAreSet: (NSObject*) object
{
    if (!object)
    {
        XCTFail("object must be set.");
        return;//Return to avoid crashing below
    }
    
    //Add here calculated properties that cannot be initialized and shouldn't be checked for initialization:
    NSDictionary* const exceptionProperties = @{
        NSStringFromClass([ADTokenCacheStoreItem class]):[NSSet setWithObjects:@"multiResourceRefreshToken", nil],
    };
    
    //Enumerate all properties and ensure that they are set to non-default values:
    unsigned int propertyCount;
    objc_property_t* properties = class_copyPropertyList([object class], &propertyCount);

    for (int i = 0; i < propertyCount; ++i)
    {
        NSString* propertyName = [NSString stringWithCString:property_getName(properties[i])
                                                    encoding:NSUTF8StringEncoding];
        NSSet* exceptions = [exceptionProperties valueForKey:NSStringFromClass([object class])];//May be nil
        if ([exceptions containsObject:propertyName])
        {
            continue;//Respect the exception
        }
        
        id value = [object valueForKey:propertyName];
        if ([value isKindOfClass:[NSNumber class]])
        {
            //Cast to the scalar to double and ensure it is far from 0 (default)
            
            double dValue = [(NSNumber*)value doubleValue];
            if (abs(dValue) < 0.0001)
            {
                XCTFail("The value of the property %@ is 0. Please update the initialization method to set it.", propertyName);
            }
        }
        else //Not a scalar type, we can compare to nil:
        {
            XCTAssertNotNil(value, "The value of the property %@ is nil. Please update the initialization method to set it.", propertyName);
        }
    }
}

-(void) adVerifyPropertiesAreSame: (NSObject*) object1
                         second: (NSObject*) object2
{
    if ((nil == object1) != (nil == object1))
    {
        XCTFail("Objects are different.");
        return;//One is nil, avoid crashing below
    }
    if (!object1)
    {
        return;//Both nil, return to avoid crashing below
    }
    
    if ([object1 class] != [object2 class])
    {
        XCTFail("Objects are instances of different classes.");
        return;//Different classes
    }
    
    //Enumerate all properties and ensure that they are set to non-default values:
    unsigned int propertyCount;
    objc_property_t* properties = class_copyPropertyList([object1 class], &propertyCount);
    
    for (int i = 0; i < propertyCount; ++i)
    {
        NSString* propertyName = [NSString stringWithCString:property_getName(properties[i])
                                                    encoding:NSUTF8StringEncoding];
        
        id value1 = [object1 valueForKey:propertyName];
        id value2 = [object2 valueForKey:propertyName];
        //Special case the types of interest. We do not want to test every single type of property,
        //as we may get a circular or runtime types:
        if (!value1)
        {
            XCTAssertNil(value2, "The value of the property %@ is not the same.", propertyName);
        }
        else if ([value1 isKindOfClass:[NSNumber class]])
        {
            //Scalar type, simply cast to double:
            double dValue1 = [(NSNumber*)value1 doubleValue];
            double dValue2 = [(NSNumber*)value2 doubleValue];
            if (abs(dValue1 - dValue2) > 0.0001)
            {
                XCTFail("The value of the property %@ is different. Value1: %@; Value2: %@", propertyName, value1, value2);
            }
        }
        else if ([value1 isKindOfClass:[NSDate class]])
        {
            //The framework is flaky with deserialization of NSDate classes:
            NSTimeInterval delta = [(NSDate*)value1 timeIntervalSinceDate:(NSDate*)value2];
            if (abs(delta) >= 1)//Sub-second tollerance
            {
                XCTFail("The value of the property %@ is not the same. Value1: %@; Value2: %@", propertyName, value1, value2);
            }
        }
        else if ([value1 isKindOfClass:[NSString class]])
        {
            if (![value1 isEqual:value2])
            {
                //Convenient to put breakpoint here:
                XCTFail("The value of the property %@ is not the same. Value1: %@; Value2: %@", propertyName, value1, value2);
            }
        }
        else if ([value1 isKindOfClass:[ADUserInformation class]])
        {
            [self adVerifyPropertiesAreSame:value1 second:value2];
        }
        else if ([value1 isKindOfClass:[NSDictionary class]])
        {
            if (![value1 isEqual:value2])
            {
                //Convenient to put breakpoint here:
                XCTFail("The value of the property %@ is not the same. Value1: %@; Value2: %@", propertyName, value1, value2);
            }
        }
        else
        {
            XCTFail("Unsupported property. Please fix this test code accordingly. ");
        }
    }
}

//Ensures that two items are the same:
-(void) adVerifySameWithItem: (ADTokenCacheStoreItem*) item1
                       item2: (ADTokenCacheStoreItem*) item2
{
    XCTAssertNotNil(item1);
    XCTAssertNotNil(item2);
    
    [self adVerifyPropertiesAreSame:item1 second:item2];
}

-(void) adCallAndWaitWithFile: (NSString*) file
                         line: (int) line
             completionSignal: (volatile int*) signal
                        block: (void (^)(void)) block
{
    THROW_ON_NIL_ARGUMENT(signal);
    THROW_ON_NIL_EMPTY_ARGUMENT(file);
    THROW_ON_NIL_ARGUMENT(block);
    
    if (*signal)
    {
        [self recordFailureWithDescription:@"The signal should be 0 before asynchronous execution."
                                    inFile:file
                                    atLine:line
                                  expected:NO];
        return;
    }
    
    block();//Run the intended asynchronous method
    
    //Set up and excuted the run loop until completion:
    NSDate* timeOut = [NSDate dateWithTimeIntervalSinceNow:10];//Waits for 10 seconds.
    while (!(*signal) && [[NSDate dateWithTimeIntervalSinceNow:0] compare:timeOut] != NSOrderedDescending)
    {
        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:timeOut];
    }
    if (!*signal)
    {
        [self recordFailureWithDescription:@"Timeout while waiting for validateAuthority callback."
         "This can also happen if the inner callback does not end with ASYNC_BLOCK_COMPLETE"
                                    inFile:file
                                    atLine:line
                                  expected:NO];
    }
    else
    {
        //Completed as expected, reset for the next execuion.
        *signal = 0;
    }
}

/* Called by the ASYNC_BLOCK_COMPLETE macro to signal the completion of the block
 and handle multiple calls of the callback. See the method above for details.*/
-(void) adAsynchInnerBlockCompleteWithFile: (NSString*) file
                                      line: (int) line
                          completionSignal: (volatile int*) signal
{
    if (!OSAtomicCompareAndSwapInt(0, 1, signal))//Signal completion
    {
        //The inner callback is called more than once.
        //Intentionally crash the test execution. As this may happen on another thread,
        //there is no reliable to ensure that a second call is not made, without just throwing.
        //Note that the test will succeed, but the test run will fail:
        NSString* message = [NSString stringWithFormat:@"Duplicate calling of the complition callback at %@(%d)", file, line];
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:message userInfo:nil];
    }
}


@end
