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
                            NSString *message,
                            NSString *additionalInformation,
                            NSInteger errorCode,
                            NSDictionary *userInfo);

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

@end

