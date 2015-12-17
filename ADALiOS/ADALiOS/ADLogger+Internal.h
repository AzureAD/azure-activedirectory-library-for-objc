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

#import "ADLogger.h"

//A simple macro for single-line logging:
#define AD_LOG(_level, _msg, _code, _correlationId, _info) [ADLogger log:_level message:_msg errorCode:_code info:_info correlationId:_correlationId]

#define FIRST_ARG(ARG,...) ARG

//Allows formatting, e.g. AD_LOG_FORMAT(ADAL_LOG_LEVEL_INFO, "Something", "Check this: %@ and this: %@", this1, this2)
//If we make this a method, we will lose the warning when the string formatting parameters do not match the actual parameters.
#define AD_LOG_F(_level, _msg, _code, _correlationId, _fmt, ...) [ADLogger log:_level message:_msg errorCode:_code correlationId:_correlationId format:_fmt, ##__VA_ARGS__ ]

#define AD_LOG_ERROR(_message, _code, _correlationId, _info)    AD_LOG(ADAL_LOG_LEVEL_ERROR, _message, _code, _correlationId, _info)
#define AD_LOG_WARN(_message, _correlationId, _info)            AD_LOG(ADAL_LOG_LEVEL_WARN, _message, AD_ERROR_SUCCEEDED, _correlationId, _info)
#define AD_LOG_INFO(_message, _correlationId, _info)            AD_LOG(ADAL_LOG_LEVEL_INFO, _message, AD_ERROR_SUCCEEDED, _correlationId, _info)
#define AD_LOG_VERBOSE(_message, _correlationId, _info)         AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _message, AD_ERROR_SUCCEEDED, _correlationId, _info)

#define AD_LOG_ERROR_F(_msg, _code, _correlationId, _fmt, ...)        AD_LOG_F(ADAL_LOG_LEVEL_ERROR, _msg, _code, _correlationId, _fmt, ##__VA_ARGS__)
#define AD_LOG_WARN_F(_msg, _correlationId, _fmt, ...)                AD_LOG_F(ADAL_LOG_LEVEL_WARN, _msg, AD_ERROR_SUCCEEDED, _correlationId, _fmt, ##__VA_ARGS__)
#define AD_LOG_INFO_F(_msg, _correlationId, _fmt, ...)                AD_LOG_F(ADAL_LOG_LEVEL_INFO, _msg, AD_ERROR_SUCCEEDED, _correlationId, _fmt, ##__VA_ARGS__)
#define AD_LOG_VERBOSE_F(_msg, _correlationId, _fmt, ...)             AD_LOG_F(ADAL_LOG_LEVEL_VERBOSE, _msg, AD_ERROR_SUCCEEDED, _correlationId, _fmt, ##__VA_ARGS__)

#ifndef DebugLog
#ifdef DEBUG
#   define DebugLog(fmt, ...) NSLog((@"%s[%d][%@] " fmt), __PRETTY_FUNCTION__, __LINE__, [[NSThread currentThread] isEqual:[NSThread mainThread]] ? @"main" : @"work", ##__VA_ARGS__);
#else
#   define DebugLog(...)
#endif
#endif

@interface ADLogger (Internal)

/*! Returns diagnostic trace data to be sent to the Auzure Active Directory servers. */
+ (NSDictionary*)adalId;

/*! Calculates a hash of the passed string. Useful for logging tokens, where we do not log
 the actual contents, but still want to log something that can be correlated. */
+ (NSString*)getHash:(NSString*)input;

+ (NSString*)getAdalVersion;

+ (NSString*)getCPUInfo;

/*! Returns previously set callback call or nil, if the user has not set such callback. */
+ (LogCallback)getLogCallBack;

/*! Main logging function. Macros like ADAL_LOG_ERROR are provided on top for convenience
 @param logLevel: The applicable priority of the logged message. Use AD_LOG_LEVEL_NO_LOG to disable all logging.
 @param message: Short text defining the operation/condition.
 @param additionalInformation: Full details. May contain parameter names, stack traces, etc. May be nil.
 @param errorCode: if an explicit error has occurred, this code will contain its code.
 */
+ (void)log:(ADAL_LOG_LEVEL)logLevel
    message:(NSString*)message
  errorCode:(NSInteger)errorCode
       info:(NSString*)additionalInformation
correlationId:(NSUUID*)correlationId;

/*! Convience logging fucntion. Allows the creation of additionalInformation strings using format strings. */
+ (void)log:(ADAL_LOG_LEVEL)level
    message:(NSString*)message
  errorCode:(NSInteger)code
correlationId:(NSUUID*)correlationId
     format:(NSString*)format, ... __attribute__((format(__NSString__, 5, 6)));

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

@end
