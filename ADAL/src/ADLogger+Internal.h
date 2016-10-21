// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADLogger.h"

//A simple macro for single-line logging:
#define AD_LOG(_level, _msg, _code, _correlationId, _dict, _info) \
    [ADLogger log:_level context:self message:_msg errorCode:_code info:_info correlationId:_correlationId userInfo:_dict]

#define FIRST_ARG(ARG,...) ARG

//Allows formatting, e.g. AD_LOG_FORMAT(ADAL_LOG_LEVEL_INFO, "Something", "Check this: %@ and this: %@", this1, this2)
//If we make this a method, we will lose the warning when the string formatting parameters do not match the actual parameters.
#define AD_LOG_F(_level, _msg, _code, _correlationId, _dict, _fmt, ...) \
    [ADLogger log:_level context:self message:_msg errorCode:_code correlationId:_correlationId userInfo:_dict format:_fmt, ##__VA_ARGS__ ]

#define AD_LOG_ERROR(_message, _code, _correlationId, _info) \
    AD_LOG(ADAL_LOG_LEVEL_ERROR, (_message), (_code), _correlationId, nil, _info)
#define AD_LOG_WARN(_message, _correlationId, _info) \
    AD_LOG(ADAL_LOG_LEVEL_WARN, _message, AD_ERROR_SUCCEEDED, _correlationId, nil, _info)
#define AD_LOG_INFO(_message, _correlationId, _info) \
    AD_LOG(ADAL_LOG_LEVEL_INFO, _message, AD_ERROR_SUCCEEDED, _correlationId, nil, _info)
#define AD_LOG_VERBOSE(_message, _correlationId, _info) \
    AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _message, AD_ERROR_SUCCEEDED, _correlationId, nil, _info)

#define AD_LOG_ERROR_F(_msg, _code, _correlationId, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_ERROR, _msg, _code, _correlationId, nil, _fmt, ##__VA_ARGS__)
#define AD_LOG_WARN_F(_msg, _correlationId, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_WARN, _msg, AD_ERROR_SUCCEEDED, _correlationId, nil, _fmt, ##__VA_ARGS__)
#define AD_LOG_INFO_F(_msg, _correlationId, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_INFO, _msg, AD_ERROR_SUCCEEDED, _correlationId, nil, _fmt, ##__VA_ARGS__)
#define AD_LOG_VERBOSE_F(_msg, _correlationId, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_VERBOSE, _msg, AD_ERROR_SUCCEEDED, _correlationId, nil, _fmt, ##__VA_ARGS__)

#define AD_LOG_ERROR_DICT(_message, _code, _correlationId, _dict, _info) \
    AD_LOG(ADAL_LOG_LEVEL_ERROR, (_message), (_code), _correlationId, _dict, _info)
#define AD_LOG_WARN_DICT(_message, _correlationId, _dict, _info) \
    AD_LOG(ADAL_LOG_LEVEL_WARN, _message, AD_ERROR_SUCCEEDED, _correlationId, _dict, _info)
#define AD_LOG_INFO_DICT(_message, _correlationId, _dict, _info) \
    AD_LOG(ADAL_LOG_LEVEL_INFO, _message, AD_ERROR_SUCCEEDED, _correlationId, _dict, _info)
#define AD_LOG_VERBOSE_DICT(_message, _correlationId, _dict, _info) \
    AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _message, AD_ERROR_SUCCEEDED, _correlationId, _dict, _info)

#define AD_LOG_ERROR_DICT_F(_msg, _code, _correlationId, _dict, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_ERROR, _msg, _code, _correlationId, _dict, _fmt, ##__VA_ARGS__)
#define AD_LOG_WARN_DICT_F(_msg, _correlationId, _dict, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_WARN, _msg, AD_ERROR_SUCCEEDED, _correlationId, _dict, _fmt, ##__VA_ARGS__)
#define AD_LOG_INFO_DICT_F(_msg, _correlationId, _dict, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_INFO, _msg, AD_ERROR_SUCCEEDED, _correlationId, _dict, _fmt, ##__VA_ARGS__)
#define AD_LOG_VERBOSE_DICT_F(_msg, _correlationId, _dict, _fmt, ...) \
    AD_LOG_F(ADAL_LOG_LEVEL_VERBOSE, _msg, AD_ERROR_SUCCEEDED, _correlationId, _dict, _fmt, ##__VA_ARGS__)

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
    context:(id)context
    message:(NSString *)message
  errorCode:(NSInteger)errorCode
       info:(NSString *)additionalInformation
correlationId:(NSUUID *)correlationId
   userInfo:(NSDictionary *)userInfo;

/*! Convience logging fucntion. Allows the creation of additionalInformation strings using format strings. */
+ (void)log:(ADAL_LOG_LEVEL)level
    context:(id)context
    message:(NSString *)message
  errorCode:(NSInteger)code
correlationId:(NSUUID *)correlationId
   userInfo:(NSDictionary *)userInfo
     format:(NSString *)format, ... __attribute__((format(__NSString__, 7, 8)));

/*! Logs obtaining of a token. The method does not log the actual token, only its hash.
 @param token: the token to log.
 @param tokenType: "access token", "refresh token", "multi-resource refresh token"
 @param expiresOn: the time when an access token will stop to be valid. Nil for refresh token types.
 @param correlationId: In case the token was just obtained from the server, the correlation id of the call.
 This parameter can be nil.
 */
+ (void)logToken:(NSString *)token
       tokenType:(NSString *)tokenType
       expiresOn:(NSDate *)expiresOn
         context:(NSString *)context
   correlationId:(NSUUID *)correlationId;

+ (void)setIdValue:(NSString*)value
            forKey:(NSString*)key;

@end
