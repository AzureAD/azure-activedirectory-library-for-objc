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

#import <XCTest/XCTest.h>
#import <ADALiOS/ADAuthenticationError.h>
#import "../ADALiOS/ADALiOS.h"

typedef enum
{
    TEST_LOG_LEVEL,
    TEST_LOG_MESSAGE,
    TEST_LOG_INFO,
    TEST_LOG_CODE,
} ADLogPart;

@class ADTokenCacheStoreItem;

@interface XCTestCase (HelperMethods)

/*! Verifies that the text is not nil, empty or containing only spaces */
-(void) assertValidText: (NSString*) text
                message: (NSString*) message;

-(void) assertStringEquals: (NSString*) actual
          stringExpression: (NSString*) expression
                  expected: (NSString*) expected
                      file: (const char*) file
                      line: (int) line;

/*! Used with the class factory methods that create class objects. Verifies
 the expectations when the passed argument is invalid:
 - The creator should return nil.
 - The error should be set accordingly, containing the argument in the description.*/
-(void) validateFactoryForInvalidArgument: (NSString*) argument
                           returnedObject: (id) returnedObject
                                    error: (ADAuthenticationError*) error;

/*! Verifies that the correct error is returned when any method was passed invalid arguments.
 */
-(void) validateForInvalidArgument: (NSString*) argument
                             error: (ADAuthenticationError*) error;

/*! Sets logging and other infrastructure for a new test */
-(void) adTestBegin;

/*! Clears logging and other infrastructure after a test */
-(void) adTestEnd;

//The methods help with verifying of the logs:
-(NSString*) adGetLogs:(ADLogPart)logPart;

//Clears all of the test logs. Useful for repeating operations.
-(void) clearLogs;

-(void) assertLogsContain: (NSString*) text
                  logPart: (ADLogPart) logPart
                     file: (const char*) file
                     line: (int) line;

-(void) assertLogsDoNotContain:  (NSString*) text
                       logPart: (ADLogPart) logPart
                          file: (const char*) file
                          line: (int) line;

//Creates an new item with all of the properties having correct values
-(ADTokenCacheStoreItem*) createCacheItem;

-(NSString*) adLogLevelLogs;
-(NSString*) adMessagesLogs;
-(NSString*) adInformationLogs;
-(NSString*) adErrorCodesLogs;

//Counts how many times the "contained" is sequentially occurring in "string".
//Example: "bar bar" is contained once in "bar bar bar" and twice in "bar bar bar bar".
-(int) adCountOccurencesOf: (NSString*) contained
                  inString: (NSString*) string;

//The methods help with verifying of the logs:
-(int) adCountOfLogOccurrencesIn: (ADLogPart) logPart
                        ofString: (NSString*) contained;

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
    [self assertStringEquals:actualParam \
        stringExpression:@"" #actualParam \
                expected:expectedParam \
                    file:__FILE__ \
                    line:__LINE__]; \
}

//Fixes the problem with the test framework not able to compare dates:
#define ADAssertDateEquals(actualParam, expectedParam) XCTAssertTrue([expectedParam compare:actualParam] == NSOrderedSame)

//Usage: ADAssertLogsContain(TEST_LOG_MESSAGE, "acquireToken");
//  ADAssertLogsContainValue(TEST_LOG_MESSAGE, parameterValue);
#define ADAssertLogsContain(LOGPART, TEXT) \
{ \
    [self assertLogsContain:TO_NSSTRING(TEXT) \
                    logPart:LOGPART \
                      file:__FILE__ \
                      line:__LINE__]; \
}

#define ADAssertLogsContainValue(LOGPART, TEXT) \
{ \
    [self assertLogsContain:TEXT \
                    logPart:LOGPART \
                       file:__FILE__ \
                       line:__LINE__]; \
}

#define ADAssertLogsDoNotContain(LOGPART, TEXT) \
{ \
    [self assertLogsDoNotContain:TO_NSSTRING(TEXT) \
                         logPart:LOGPART \
                            file:__FILE__ \
                            line:__LINE__]; \
}

#define ADAssertLogsDoNotContainValue(LOGPART, TEXT) \
{ \
    [self assertLogsDoNotContain:TEXT \
                         logPart:LOGPART \
                            file:__FILE__ \
                            line:__LINE__];\
}

//Verifes that "error" local variable is nil. If not prints the error
#define ADAssertNoError XCTAssertNil(error, "Unexpected error occurred: %@", error.errorDetails)

