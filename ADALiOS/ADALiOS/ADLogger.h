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

/*! Levels of logging. Defines the priority of the logged message */
#import <Foundation/Foundation.h>

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
+ (void)setLevel:(ADAL_LOG_LEVEL)logLevel;

/*! Returns the current log level. See setLevel for details */
+ (ADAL_LOG_LEVEL)getLevel;


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
+ (void)setLogCallBack:(LogCallback)callback;

/*! By default, logging sends messages through standard NSLog. This function allows to disable this
 behavior. Disabling is useful if faster logging is implemented through the callback. */
+ (void)setNSLogging:(BOOL)nslogging;

/*! YES if the messages are logged through NSLog.*/
+ (BOOL)getNSLogging;

/*! Sets correlation id to be used in the requests sent to server. */
+ (void)setCorrelationId:(NSUUID*)correlationId;

/*! Gets correlation Id. */
+ (NSUUID*)getCorrelationId;

@end

