/*
 Copyright © Microsoft. All rights reserved.
 
 Synopsis:  CUTLogger protocol definition.
 
 Owner: yiweizha
 Created: 9/26/2012
 */

#import <Foundation/Foundation.h>
#import "CUTLogWriter.h"
#import "CUTLoggerSettings.h"

#pragma mark - Enums

/**
 @details Event logging levels
 */
typedef NS_ENUM(NSUInteger, CUTTraceLevel)
{
    CUTTraceLevelAssert      = 1,
    CUTTraceLevelError       = 1<<1,
    CUTTraceLevelWarning     = 1<<2,
    CUTTraceLevelInfo        = 1<<3,
    CUTTraceLevelVerbose     = 1<<4,
    CUTTraceLevelPerformance = 1<<5,
    CUTTraceLevelFunction    = 1<<6,
    CUTTraceLevelMemory      = 1<<7,
};

/**
 @details Event code to be logged
 */
typedef NS_ENUM(NSUInteger, CUTTraceEventCode)
{
    CUTTraceEventDefault      = 0,
    CUTTraceEventStart        = 1,
    CUTTraceEventEnd          = 2,
    CUTTraceEventCall         = 3,
    CUTTraceEventReturn       = 4
};

/**
 @details Event logging configuration. It specifies if certain entities (timestamp, file name, function name, etc) will be logged. 
  In the logger settings we have a config mask value based on the following enumration determines which entities to be logged
 */
typedef NS_ENUM(NSUInteger, CUTLogConfig)
{
    CUTLogTimeStamp   = 1,
    CUTLogFunction    = 1<<1,
    CUTLogFileName    = 1<<2,
    CUTLogLineNumber  = 1<<3,
    CUTLogThreadID    = 1<<4
};


/**
 @details Protocol for logger. The client needs to implement a logger with the following protocol to trace info
 */
@protocol CUTLogger<NSObject>

/**
 @brief Check condtion and write an event out to the log.
 @param condition   Assert condition
 @param function    Function name
 @param line        Current line number
 @param fileName    Current file name
 @param domain      Component domain
 @param eventCode   Event code
 @param eventID     Event ID
 @param message     Message to be logged
 */
- (BOOL) assertCondition:(BOOL)condition
        withFunctionName:(const char *)function
                  atLine:(long)line
                  inFile:(const char *)filename
                inDomain:(NSString *)domain
           withEventCode:(CUTTraceEventCode)eventCode
              andEventID:(NSUInteger)eventID
            withActivity:(NSString *)activity
             withMessage:(NSString *)message;

/**
 @brief Write info out to the log.
 @param function    Function name
 @param line        Current line number
 @param fileName    Current file name
 @param level       Event severity level
 @param domain      Component domain
 @param eventCode   Event code
 @param eventID     Event ID
 @param message     Message to be logged
 */
- (void)traceWithFunctionName:(const char *)function
                       atLine:(long)line
                       inFile:(const char *)filename
                     forLevel:(CUTTraceLevel)level
                     inDomain:(NSString *)domain
                withEventCode:(CUTTraceEventCode)eventCode
                   andEventID:(NSUInteger)eventID
                 withActivity:(NSString *)activity
                  withMessage:(NSString *)message;

/**
 @brief Write an event with error out to the log.
 @param function    Function name
 @param line        Current line number
 @param fileName    Current file name
 @param level       Event severity level
 @param domain      Component domain
 @param eventCode   Event code
 @param eventID     Event ID
 @param activity    User defined string correlates log entries
 @param message     Message to be logged
 @param error       Instance of error to be logged, if any
 */
- (void)traceWithFunctionName:(const char *)function
                       atLine:(long)line
                       inFile:(const char *)filename
                     forLevel:(CUTTraceLevel)level
                     inDomain:(NSString *)domain
                withEventCode:(CUTTraceEventCode)eventCode
                   andEventID:(NSUInteger)eventID
                 withActivity:(NSString *)activity
                  withMessage:(NSString *)message
                     andError:(NSError *)error;

/**
 @brief Set the logger settings.
 @param Logger settings
 */
- (void)setLoggerSettings:(CUTLoggerSettings *) loggerSettings;

/**
 @brief  Add a log writer instance
 @param  Log writer instance
 */
- (void) addLogWriter:(id<CUTLogWriter>) instance;


- (id<CUTLogWriter>) getLogWriter;

/**
 @brief Clears the logs from all added log writers.
 */
- (void)clearLogs;

@end

