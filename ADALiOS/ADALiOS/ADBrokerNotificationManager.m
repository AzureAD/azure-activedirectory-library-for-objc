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

#import "ADBrokerNotificationManager.h"
#import "ADAL.h"
#import "ADAuthenticationResult+Internal.h"
@interface ADBrokerNotificationManager ()
{
    ADAuthenticationCallback _callbackForBroker;
}

@end

@implementation ADBrokerNotificationManager

-(id) init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id) initInternal
{
    self = [super init];
    return self;
}

+(ADBrokerNotificationManager*)sharedInstance
{
    /* Below is a standard objective C singleton pattern*/
    static ADBrokerNotificationManager* instance;
    static dispatch_once_t onceToken;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[ADBrokerNotificationManager alloc] initInternal];
        });
    }
    return instance;
}


-(void) enableOnActiveNotification:(ADAuthenticationCallback) callback
{
    _callbackForBroker = callback;
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(callbackCleanup)
                                                 name:UIApplicationDidBecomeActiveNotification object:nil];
    
}

- (ADAuthenticationCallback)copyAndClearCallback
{
    ADAuthenticationCallback callback = nil;
    @synchronized(self)
    {
        callback = _callbackForBroker;
        _callbackForBroker = nil;
    }
    
    return callback;
}

- (void)callbackCleanup
{
    // We're not guaranteed the order that notifications happen in. Put this on the back of the main event queue so that
    // launchURL might have a chance at the callback first.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        ADAuthenticationCallback callback = [self copyAndClearCallback];
        
        if(callback)
        {
            ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BROKER_RESPONSE_NOT_RECEIVED
                                                                                    protocolCode:nil
                                                                                    errorDetails:@"application did not receive response from broker."];
            ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:adError];
            callback(result);
        }
        
        [[NSNotificationCenter defaultCenter] removeObserver:self
                                                        name:UIApplicationDidBecomeActiveNotification
                                                      object:nil];
    });
}


@end
