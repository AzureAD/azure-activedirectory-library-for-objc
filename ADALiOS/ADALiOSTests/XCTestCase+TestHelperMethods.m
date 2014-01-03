// Created by Boris Vidolov on 10/24/13.
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
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALioS/ADAuthenticationSettings.h>


@implementation XCTestCase (TestHelperMethods)

//Tracks the logged messages.
NSMutableString* sLogLevelsLog;
NSMutableString* sMessagesLog;
NSMutableString* sInformationLog;
NSMutableString* sErrorCodesLog;

NSString* sTestBegin = @"|||TEST_BEGIN|||";
NSString* sTestEnd = @"|||TEST_END|||";

/*! See header for comments */
-(void) assertValidText: (NSString*) text
                message: (NSString*) message
{
    //The pragmas here are copied directly from the XCTAssertNotNil:
    _Pragma("clang diagnostic push")
    _Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"")//Temporarily remove the compiler warning
    if ([NSString isStringNilOrBlank:text])
    {
        _XCTFailureHandler(self, YES, __FILE__, __LINE__, text, message);
    }
    _Pragma("clang diagnostic pop")//Restore the compiler warning
}

/* See header for details. */
-(void) validateForInvalidArgument: (NSString*) argument
                             error: (ADAuthenticationError*) error
{
    XCTAssertNotNil(argument, "Internal test error: please specify the expected parameter.");
    
    
    XCTAssertNotNil(error, "Error should be raised for the invalid argument '%@'", argument);
    XCTAssertNotNil(error.domain, "Error domain is nil.");
    XCTAssertEqual(error.domain, ADInvalidArgumentDomain, "Incorrect error domain.");
    XCTAssertNil(error.protocolCode, "The protocol code should not be set. Instead protocolCode ='%@'.", error.protocolCode);
    
    [self assertValidText:error.errorDetails message:@"The error should have details."];
    NSString* argumentString = [NSString stringWithFormat:@"'%@'", argument];
    BOOL found = [error.errorDetails containsString:argumentString];
    XCTAssertTrue(found, "The parameter is not specified in the error details. Error details:%@", error.errorDetails);
}


/* See header for details.*/
-(void) validateFactoryForInvalidArgument: (NSString*) argument
                           returnedObject: (id) returnedObject
                                    error: (ADAuthenticationError*) error
{
    XCTAssertNil(returnedObject, "Creator should have returned nil. Object: %@", returnedObject);
    
    [self validateForInvalidArgument:argument error:error];
}

/*! Sets logging and other infrastructure for a new test */
-(void) adTestBegin
{
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
        }
    };

    
    [ADLogger setLogCallBack:logCallback];
    [ADLogger setLevel:ADAL_LOG_LAST];//Log everything by default. Tests can change this.
    [ADLogger setNSLogging:NO];//Disables the NS logging to avoid generating huge amount of system logs.
    XCTAssertEqual(logCallback, [ADLogger getLogCallBack], "Setting of logCallBack failed.");
    //Tests are executed in the main thread and as such, they will fail, if the asynchronous methods dispatch to the same thread,
    //so we redirect dispatching to the background asynchronous queue:
    [ADAuthenticationSettings sharedInstance].dispatchQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
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

-(void) clearLogs
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

-(void) assertLogsContain: (NSString*) text
                  logPart: (ADLogPart) logPart
                     file: (const char*) file
                     line: (int) line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if (![logs containsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test do not contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

-(void) assertLogsDoNotContain: (NSString*) text
                       logPart: (ADLogPart) logPart
                          file: (const char*) file
                          line: (int) line
{
    NSString* logs = [self adGetLogs:logPart];
    
    if ([logs containsString:text])
    {
        _XCTFailureHandler(self, YES, file, line, @"Logs.", @"" "Logs for the test contain '%@'. Part of the log examined: %u", text, logPart);
    }
}

-(void) assertStringEquals: (NSString*) actual
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
-(ADTokenCacheStoreItem*) createCacheItem
{
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net";
    item.clientId = @"client id";
    item.accessToken = @"access token";
    item.refreshToken = @"refresh token";
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    ADAuthenticationError* error;
    ADUserInformation* info = [ADUserInformation userInformationWithUserId:@"userId" error:&error];
    ADAssertNoError;
    XCTAssertNotNil(info, "Nil user info returned.");
    item.userInformation = info;
    item.tenantId = @"msopentech.com";
    
    return item;
}

@end
