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
#import "ADAL_Internal.h"
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


- (void)enableNotifications:(ADAuthenticationCallback)callback
{
    @synchronized(self)
    {
        _callbackForBroker = callback;
    }
    
    // UIApplicationDidBecomeActive can get hit after the iOS 9 "This app wants to open this other app"
    // dialog is displayed. Because of the multitude of ways that notification can be sent we can't rely
    // merely on it to be able to accurately decide when we need to clean up. According to Apple's
    // documentation on the app lifecycle when receiving a URL we should be able to rely on openURL:
    // occuring between ApplicationWillEnterForeground and ApplicationDidBecomeActive.
    
    // https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW8
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onEnterForeground:)
                                                 name:UIApplicationWillEnterForegroundNotification object:nil];
    
}

- (void)onEnterForeground:(NSNotification*)aNotification
{
    (void)aNotification;
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:UIApplicationWillEnterForegroundNotification
                                                  object:nil];
    
    // Now that we know we've just been woken up from having been in the background we can start listening for
    // ApplicationDidBecomeActive without having to worry about something else causing it to get hit between
    // now and openURL:, if we're indeed getting a URL.
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(callbackCleanup:)
                                                 name:UIApplicationDidBecomeActiveNotification object:nil];
}

- (ADAuthenticationCallback)copyAndClearCallback
{
    // Whoever calls this and takes the callback owns it. We don't want multiple listeners to
    // inadvertantly take this callback.
    ADAuthenticationCallback callback = nil;
    @synchronized(self)
    {
        callback = _callbackForBroker;
        _callbackForBroker = nil;
    }
    
    return callback;
}

- (void)callbackCleanup:(NSNotification*)aNotification
{
    (void)aNotification;
    
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:UIApplicationDidBecomeActiveNotification
                                                  object:nil];
    
    ADAuthenticationCallback callback = [self copyAndClearCallback];

    // If there's still a callback block it means the user opted not to continue with the authentication flow
    // in the broker and we should let whoever is waiting on an ADAL response know it's not coming.
    if(callback)
    {
        ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BROKER_RESPONSE_NOT_RECEIVED
                                                                                protocolCode:nil
                                                                                errorDetails:@"application did not receive response from broker."];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:adError];
        callback(result);
    }
}


@end
