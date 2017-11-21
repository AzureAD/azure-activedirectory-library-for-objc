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

#define AD_LOG(_level, _correlationId, _isPii, _fmt, ...) \
    [ADLogger log:_level context:self correlationId:_correlationId isPii:_isPii format:_fmt, ##__VA_ARGS__]

#define FIRST_ARG(ARG,...) ARG

#define AD_LOG_ERROR(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_ERROR, _correlationId, NO, _fmt, ##__VA_ARGS__)

#define AD_LOG_ERROR_PII(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_ERROR, _correlationId, YES, _fmt, ##__VA_ARGS__)

#define AD_LOG_WARN(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_WARN, _correlationId, NO, _fmt, ##__VA_ARGS__)

#define AD_LOG_WARN_PII(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_WARN, _correlationId, YES, _fmt, ##__VA_ARGS__)

#define AD_LOG_INFO(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_INFO, _correlationId, NO, _fmt, ##__VA_ARGS__)

#define AD_LOG_INFO_PII(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_INFO, _correlationId, YES, _fmt, ##__VA_ARGS__)

#define AD_LOG_VERBOSE(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _correlationId, NO, _fmt, ##__VA_ARGS__)

#define AD_LOG_VERBOSE_PII(_correlationId, _fmt, ...) \
    AD_LOG(ADAL_LOG_LEVEL_VERBOSE, _correlationId, YES, _fmt, ##__VA_ARGS__)

#ifndef DebugLog
#ifdef DEBUG
#   define DebugLog(fmt, ...) NSLog((@"%s[%d][%@] " fmt), __PRETTY_FUNCTION__, __LINE__, [[NSThread currentThread] isEqual:[NSThread mainThread]] ? @"main" : @"work", ##__VA_ARGS__);
#else
#   define DebugLog(...)
#endif
#endif

@interface ADLogger (Internal)

/*! Calculates a hash of the passed string. Useful for logging tokens, where we do not log
 the actual contents, but still want to log something that can be correlated. */
+ (NSString*)getHash:(NSString*)input;

/*! Returns previously set callback call or nil, if the user has not set such callback. */
+ (LogCallback)getLogCallBack;

+ (void)log:(ADAL_LOG_LEVEL)level
    context:(id)context
correlationId:(NSUUID *)correlationId
      isPii:(BOOL)isPii
     format:(NSString *)format, ... __attribute__((format(__NSString__, 5, 6)));

/*! Logs obtaining of a token. The method does not log the actual token, only its hash.
 @param token The token to log.
 @param tokenType "access token", "refresh token", "multi-resource refresh token"
 @param expiresOn The time when an access token will stop to be valid. Nil for refresh token types.
 @param correlationId In case the token was just obtained from the server, the correlation id of the call.
 This parameter can be nil.
 */
+ (void)logToken:(NSString *)token
       tokenType:(NSString *)tokenType
       expiresOn:(NSDate *)expiresOn
         context:(NSString *)context
   correlationId:(NSUUID *)correlationId;

@end
