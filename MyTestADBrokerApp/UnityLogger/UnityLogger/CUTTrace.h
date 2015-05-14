/*
 Copyright © 2013 Microsoft. All rights reserved.
 
 Synopsis:  Macros for trace in the library.
 
 Owner: yiweizha
 Created: 9/26/2013
 */

#import <Foundation/Foundation.h>
#import "CUTLibrary.h"

// Trace macros
#define CUTTrace(level, domain, message, ...) [[CUTLibrary sharedLogger] traceWithFunctionName:__PRETTY_FUNCTION__ atLine:__LINE__ inFile:__FILE__ forLevel:(CUTTraceLevel)(level) inDomain:domain withEventCode:CUTTraceEventDefault andEventID:0 withActivity:nil withMessage:[NSString stringWithFormat:(message), ##__VA_ARGS__]]

// Trace only for debug
#ifdef DEBUG 
    #define CUTTraceDebug(level, domain, message, ...) CUTTrace(level, domain, message, ##__VA_ARGS__)
#else
    #define CUTTraceDebug(level, domain, message, ...) {}
#endif

// Trace error macros
#define CUTTraceError(level, domain, error, message, ...) [[CUTLibrary sharedLogger] traceWithFunctionName:__PRETTY_FUNCTION__ atLine:__LINE__ inFile:__FILE__ forLevel:(CUTTraceLevel)(level) inDomain:domain withEventCode:CUTTraceEventDefault andEventID:0 withActivity:nil withMessage:[NSString stringWithFormat:(message), ##__VA_ARGS__] andError:error];

// Trace event macros
#define CUTTraceEvent(level, domain, eventCode, eventID, message, ...) [[CUTLibrary sharedLogger] traceWithFunctionName:__PRETTY_FUNCTION__ atLine:__LINE__ inFile:__FILE__ forLevel:(CUTTraceLevel)(level) inDomain:domain withEventCode:(CUTTraceEventCode)(eventCode) andEventID:eventID withActivity:nil withMessage:[NSString stringWithFormat:(message), ##__VA_ARGS__]];

// Assert macros
#define CUTAssert(condition, domain, message, ...)   [[CUTLibrary sharedLogger] assertCondition:condition withFunctionName:__PRETTY_FUNCTION__ atLine:__LINE__ inFile:__FILE__ inDomain:domain  withEventCode:CUTTraceEventDefault andEventID:0 withActivity:nil withMessage:[NSString stringWithFormat:(message), ##__VA_ARGS__]];

// Validation macros
#define CUTAssertAndReturnIfFalse(condition, domain, message, ...) \
if( !(condition) ) {                                  \
CUTAssert(condition, domain, message, ##__VA_ARGS__); \
return;                                               \
}

#define CUTAssertAndReturnValueIfFalse(condition, value, domain, message, ...) \
if( !(condition) ) {                                  \
CUTAssert(condition, domain, message, ##__VA_ARGS__); \
return (value);                                       \
}
