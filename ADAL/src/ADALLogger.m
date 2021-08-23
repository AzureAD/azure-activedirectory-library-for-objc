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

#import "ADALLogger.h"
#import "MSIDLogger+Internal.h"

static LogCallback s_OldCallback = nil;
static ADLoggerCallback s_LoggerCallback = nil;

static NSMutableDictionary* s_adalFullMetadata = nil;

@implementation ADALLogger

#pragma mark - Log callback

+ (void)load
{
    [self setupLogCallback];
}

+ (void)setupLogCallback
{
    // Because ADAL theoretically allows changing log callbacks, ADLogger will register its own callback and forward logs
    // We want the shared callback to be set as early as possible
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[MSIDLogger sharedLogger] setCallback:^(MSIDLogLevel level, NSString *message, BOOL containsPII) {
            
            @synchronized (self) //Guard against thread-unsafe callback and modification of sLogCallback after the check
            {
                if (s_LoggerCallback)
                {
                    s_LoggerCallback((ADAL_LOG_LEVEL)level, message, containsPII);
                }
                else if (s_OldCallback)
                {
                    NSString *msg = containsPII ? @"PII message" : message;
                    NSString *additionalMessage = containsPII ? message : nil;
                    
                    s_OldCallback((ADAL_LOG_LEVEL)level, msg, additionalMessage, 0, nil);
                }
            }
        }];
    });
}

+ (void)setLogCallBack:(LogCallback)callback
{
    @synchronized (self)
    {
        s_OldCallback = [callback copy];
    }
}

+ (void)setLoggerCallback:(ADLoggerCallback)callback
{
    @synchronized (self)
    {
        s_LoggerCallback = [callback copy];
    }
}

+ (void)setLevel:(ADAL_LOG_LEVEL)logLevel
{
    [MSIDLogger sharedLogger].level = (MSIDLogLevel)logLevel;
}

+ (ADAL_LOG_LEVEL)getLevel
{
    return (ADAL_LOG_LEVEL)[MSIDLogger sharedLogger].level;
}

#pragma mark - NSLogging

+ (void)setNSLogging:(BOOL)nslogging
{
    [MSIDLogger sharedLogger].NSLoggingEnabled = nslogging;
}

+ (BOOL)getNSLogging
{
    return [MSIDLogger sharedLogger].NSLoggingEnabled;
}

#pragma mark - Pii switch

+ (void)setPiiEnabled:(BOOL)piiEnabled
{
    [MSIDLogger sharedLogger].PiiLoggingEnabled = piiEnabled;
}

+ (BOOL)getPiiEnabled
{
    return [MSIDLogger sharedLogger].PiiLoggingEnabled;
}

@end
