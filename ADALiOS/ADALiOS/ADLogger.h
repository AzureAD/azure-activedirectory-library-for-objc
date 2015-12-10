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

/*! Main logging function. Macros like ADAL_LOG_ERROR are provided on top for convenience
 @param logLevel: The applicable priority of the logged message. Use AD_LOG_LEVEL_NO_LOG to disable all logging.
 @param message: Short text defining the operation/condition.
 @param additionalInformation: Full details. May contain parameter names, stack traces, etc. May be nil.
 @param errorCode: if an explicit error has occurred, this code will contain its code.
 */
+ (void)log:(ADAL_LOG_LEVEL)logLevel
    message:(NSString*)message
  errorCode:(NSInteger)errorCode
       info:(NSString*)additionalInformation;

/*! Convience logging fucntion. Allows the creation of additionalInformation strings using format strings. */
+ (void)log:(ADAL_LOG_LEVEL)level
    message:(NSString*)message
  errorCode:(NSInteger)code
     format:(NSString*)format, ... __attribute__((format(__NSString__, 4, 5)));

/*! Logs obtaining of a token. The method does not log the actual token, only its hash.
 @param token: the token to log.
 @param tokenType: "access token", "refresh token", "multi-resource refresh token"
 @param expiresOn: the time when an access token will stop to be valid. Nil for refresh token types.
 @param correlationId: In case the token was just obtained from the server, the correlation id of the call.
 This parameter can be nil.
 */
+ (void)logToken:(NSString*)token
       tokenType:(NSString*)tokenType
       expiresOn:(NSDate*)expiresOn
   correlationId:(NSUUID*)correlationId;


//The block declaration. Needs to be weak to ensure that the pointer does not hold static reference
//to the parent class of the callback.
typedef void (^ADLogCallback)(ADAL_LOG_LEVEL logLevel,
                              NSString* message,
                              NSString* additionalInformation,
                              NSInteger errorCode);

/*! Provided block will be called when the logged messages meet the priority threshold
 @param callback: The block to be executed when suitable messages are logged. By default, when
 callback is set, messages will contingue to be logged through NSLog. Such logging can be disabled
 through setNSLogging. */
+ (void) setLogCallBack:(ADLogCallback) callback;

/*! Returns previously set callback call or nil, if the user has not set such callback. */
+ (ADLogCallback)getLogCallBack;

/*! By default, logging sends messages through standard NSLog. This function allows to disable this
 behavior. Disabling is useful if faster logging is implemented through the callback. */
+ (void)setNSLogging:(BOOL)nslogging;

/*! YES if the messages are logged through NSLog.*/
+ (BOOL)getNSLogging;

/*! Returns diagnostic trace data to be sent to the Auzure Active Directory servers. */
+ (NSDictionary*)adalId;

/*! Calculates a hash of the passed string. Useful for logging tokens, where we do not log
 the actual contents, but still want to log something that can be correlated. */
+ (NSString*)getHash:(NSString*)input;

/*! Sets correlation id to be used in the requests sent to server. */
+ (void)setCorrelationId:(NSUUID*)correlationId;

/*! Gets correlation Id. */
+ (NSUUID*)getCorrelationId;

+ (NSString*)getAdalVersion;

@end

//A simple macro for single-line logging:
#define AD_LOG(_level, _msg, _code, _info) [ADLogger log:_level message:_msg errorCode:_code info:_info]

#define FIRST_ARG(ARG,...) ARG

//Allows formatting, e.g. AD_LOG_FORMAT(ADAL_LOG_LEVEL_INFO, "Something", "Check this: %@ and this: %@", this1, this2)
//If we make this a method, we will lose the warning when the string formatting parameters do not match the actual parameters.
#define AD_LOG_F(_level, _msg, _code, _fmt, ...) [ADLogger log:_level message:_msg errorCode:_code format:_fmt, ##__VA_ARGS__ ]

#define AD_LOG_ERROR(_message, _code, _info)    AD_LOG(ADAL_LOG_LEVEL_ERROR, _message, _code, _info)
#define AD_LOG_WARN(_message, _info)            AD_LOG(ADAL_LOG_LEVEL_WARN, _message, AD_ERROR_SUCCEEDED, _info)
#define AD_LOG_INFO(_message, _info)            AD_LOG(ADAL_LOG_LEVEL_INFO, _message, AD_ERROR_SUCCEEDED, _info)
#define AD_LOG_VERBOSE(_message, _info)         AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _message, AD_ERROR_SUCCEEDED, _info)

#define AD_LOG_ERROR_F(_msg, _code, _fmt, ...)        AD_LOG_F(ADAL_LOG_LEVEL_ERROR, _msg, _code, _fmt, ##__VA_ARGS__)
#define AD_LOG_WARN_F(_msg, _fmt, ...)                AD_LOG_F(ADAL_LOG_LEVEL_WARN, _msg, AD_ERROR_SUCCEEDED, _fmt, ##__VA_ARGS__)
#define AD_LOG_INFO_F(_msg, _fmt, ...)                AD_LOG_F(ADAL_LOG_LEVEL_INFO, _msg, AD_ERROR_SUCCEEDED, _fmt, ##__VA_ARGS__)
#define AD_LOG_VERBOSE_F(_msg, _fmt, ...)             AD_LOG_F(ADAL_LOG_LEVEL_VERBOSE, _msg, AD_ERROR_SUCCEEDED, _fmt, ##__VA_ARGS__)

#ifndef DebugLog
#ifdef DEBUG
#   define DebugLog(fmt, ...) NSLog((@"%s[%d][%@] " fmt), __PRETTY_FUNCTION__, __LINE__, [[NSThread currentThread] isEqual:[NSThread mainThread]] ? @"main" : @"work", ##__VA_ARGS__);
#else
#   define DebugLog(...)
#endif
#endif

