// Created by Boris Vidolov on 10/25/13.
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

#import <Foundation/Foundation.h>
#import <ADALiOS/ADErrorCodes.h>

/*! Levels of logging. Defines the priority of the logged message */
typedef enum
{
    ADAL_LOG_LEVEL_NO_LOG,//Available to fully disable logging
    ADAL_LOG_LEVEL_ERROR,//Default
    ADAL_LOG_LEVEL_WARN,
    ADAL_LOG_LEVEL_INFO,
    ADAL_LOG_LEVEL_VERBOSE,
    ADAL_LOG_LAST = ADAL_LOG_LEVEL_VERBOSE,
} ADAL_LOG_LEVEL;
@interface ADLogger : NSObject

/*! Sets the logging level for the internal logging messages. Messages with
 priority lower than the specified level will be ignored. 
 @param logLevel: desired logging level. The higher the number, the more logging information is included. */
+(void) setLevel: (ADAL_LOG_LEVEL)logLevel;

/*! Returns the current log level. See setLevel for details */
+(ADAL_LOG_LEVEL) getLevel;

/*! Main logging function. Macros like ADAL_LOG_ERROR are provided on top for convenience
 @param logLevel: The applicable priority of the logged message. Use AD_LOG_LEVEL_NO_LOG to disable all logging.
 @param message: Short text defining the operation/condition.
 @param additionalInformation: Full details. May contain parameter names, stack traces, etc. May be nil.
 @param errorCode: if an explicit error has occurred, this code will contain its code.
 */
+(void) log: (ADAL_LOG_LEVEL)logLevel
    message: (NSString*) message
additionalInformation: (NSString*) additionalInformation
  errorCode: (NSInteger) errorCode;

//The block declaration. Needs to be weak to ensure that the pointer does not hold static reference
//to the parent class of the callback.
typedef void (^LogCallback)(ADAL_LOG_LEVEL logLevel,
                            NSString* message,
                            NSString* additionalInformation,
                            NSInteger errorCode);

/*! Provided block will be called when the logged messages meet the priority threshold
 @param callback: The block to be executed when suitable messages are logged. By default, when
 callback is set, messages will contingue to be logged through NSLog. Such logging can be disabled
 through setNSLogging. */
+(void) setLogCallBack: (LogCallback) callback;

/*! Returns previously set callback call or nil, if the user has not set such callback. */
+(LogCallback) getLogCallBack;

/*! By default, logging sends messages through standard NSLog. This function allows to disable this
 behavior. Disabling is useful if faster logging is implemented through the callback. */
+(void) setNSLogging: (BOOL) nslogging;

/*! YES if the messages are logged through NSLog.*/
+(BOOL) getNSLogging;

@end

#define AD_LOG(level, msg, info, code) \
{ \
            [ADLogger log: level \
                  message: msg \
    additionalInformation: info \
                errorCode: code]; \
}

#define AD_LOG_ERROR(message, info, code) AD_LOG(ADAL_LOG_LEVEL_ERROR, message, info, code);

#define AD_LOG_WARN(message, info) AD_LOG(ADAL_LOG_LEVEL_WARN, message, info, AD_ERROR_SUCCEEDED);
#define AD_LOG_INFO(message, info) AD_LOG(ADAL_LOG_LEVEL_INFO, message, info, AD_ERROR_SUCCEEDED);
#define AD_LOG_VERBOSE(message, info) AD_LOG(ADAL_LOG_LEVEL_VERBOSE, message, info, AD_ERROR_SUCCEEDED);
