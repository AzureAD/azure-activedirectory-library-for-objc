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

#import <Foundation/Foundation.h>

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

@interface ADALLogger : NSObject

/*!
    Sets the logging level for the internal logging messages. Messages with 
    priority lower than the specified level will be ignored.
 
    @param logLevel     the maximum level of information to log, any messages
 */
+ (void)setLevel:(ADAL_LOG_LEVEL)logLevel;

/*! @return the current log level */
+ (ADAL_LOG_LEVEL)getLevel;

/*!
 ADAL provides logging callbacks that assist in diagnostics. There is a boolean value in the logging callback that indicates whether the message contains user information. If piiEnabled is set to NO, the callback will not be triggered for log messages that contain any user information. By default the library will not return any messages with user information in them.
 @param piiEnabled     PII on/off flag.
 */
+ (void)setPiiEnabled:(BOOL)piiEnabled;

/*! @return the current pii flag value */
+ (BOOL)getPiiEnabled;

/*!
 The LogCallback block for the ADAL logger
 
 @param  logLevel        The level of the log message
 @param  message         A short log message describing the event that occurred, this string will not contain PII.
 @param  additionalInfo  A longer message that may contain PII and other details relevant to the event.
 @param  errorCode       An integer error code if the log message is an error.
 @param  userInfo        A dictionary with other information relevant to the log message. The information varies,
 for most error messages the error object will be in the "error" key.
 */
typedef void (^LogCallback)(ADAL_LOG_LEVEL logLevel,
                            NSString * _Nonnull message,
                            NSString * _Nullable additionalInfo,
                            NSInteger errorCode,
                            NSDictionary * _Nullable userInfo);

/*!
    Sets a block for the ADAL logger to use to send log messages to.
 
    @param callback     The block log messages are sent to. See the documentation for LogCallback for more information.
 */
+ (void)setLogCallBack:(nullable LogCallback)callback __attribute((deprecated("Use the setLoggerCallback: method instead.")));


/*!
 The LogCallback block for the ADAL logger
 
 @param  logLevel        The level of the log message
 @param  message         A short log message describing the event that occurred, this string will not contain PII.
 @param  containsPii     If the message might contain Personally Identifiable Information (PII) this will be true. Log messages possibly containing PII will not be sent to the callback unless piiEnabled is set to YES on the logger.
 */
typedef void (^ADLoggerCallback)(ADAL_LOG_LEVEL logLevel,
                                 NSString * _Nonnull message,
                                 BOOL containsPii);

+ (void)setLoggerCallback:(nullable ADLoggerCallback)callback;

/*!
    Turns on or off ADAL printing log messages to the console via NSLog. On by default.
 */
+ (void)setNSLogging:(BOOL)nslogging;

/*!
    @return Whether ADAL is currently configured to print log messages to the console via NSLog.
 */
+ (BOOL)getNSLogging;

@end

