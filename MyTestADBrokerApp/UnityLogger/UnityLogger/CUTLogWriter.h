/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  CUTLogWriter protocol definition
 
 Owner:     Yiwei Zhang
 Created:   10/06/2013
 */

/**
 @details Logger related error codes.
 */

#import <Foundation/Foundation.h>
typedef NS_ENUM(NSInteger, CUTLoggerErrorCode)
{
    CUTLoggerErrorFileNotFound   = 101,
};

/**
 @details Logger error domain.
 */
extern NSString *const kCUTLoggerDomain;

/**
 @details Trace info that contains the string representation for all the fields
 */
@interface CUTTraceInfo : NSObject

/** @brief Date string within the log. **/
@property (nonatomic, strong) NSString *dateString;

/** @brief Level info of the log. **/
@property (nonatomic, strong) NSString *levelInfo;

/** @brief Domain that the trace ocurs. **/
@property (nonatomic, strong) NSString *domain;

/** @brief File name that the trace occurs. **/
@property (nonatomic, strong) NSString *fileName;

/** @brief Function name the trace occurs. **/
@property (nonatomic, strong) NSString *functionName;

/** @brief Line number the trace occurs. **/
@property (nonatomic, strong) NSString *lineNumber;

/** @brief Event ID within the log. **/
@property (nonatomic, strong) NSString *eventIdString;

/** @brief Event code within the log. **/
@property (nonatomic, strong) NSString *eventCodeString;

/** @brief Thread info when trace occurs. **/
@property (nonatomic, strong) NSString *threadInfo;

/** @brief Activity string within the log. **/
@property (nonatomic, strong) NSString *activity;

/** @brief User supplied message. **/
@property (nonatomic, strong) NSString *message;

/** @brief The formatted string that holds all the info **/
@property (nonatomic, strong) NSString *formattedString;

@end

/**
 @details Protocol for log writers that actually write the logs somewhere
 */
@protocol CUTLogWriter <NSObject>

/**
 @brief Write an event out to the log.
 @param An instance that contains all the string represented elements within the trace info
 */
-(void)writeLogWithInfo:(CUTTraceInfo *)traceInfo;

/**
 @brief Get the log data from log file
 @param completion   A block which receives the log data, encoding type and possible error.
 */
-(void) fetchLogDataWithCompletion:(void (^)(NSData *, NSStringEncoding, NSError *))completion;

/**
 @brief Clear all log files
 */
-(void) clearLogs;

@end
