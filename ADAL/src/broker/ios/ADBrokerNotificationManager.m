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

#import "ADBrokerNotificationManager.h"
#import "ADAL_Internal.h"
#import "MSIDError.h"
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
    
    // If the broker app itself requested a token, we don't care if it goes to background or not - the
    // user should be able to continue the flow regardless
#if !AD_BROKER
    // UIApplicationDidBecomeActive can get hit after the iOS 9 "This app wants to open this other app"
    // dialog is displayed. Because of the multitude of ways that notification can be sent we can't rely
    // merely on it to be able to accurately decide when we need to clean up. According to Apple's
    // documentation on the app lifecycle when receiving a URL we should be able to rely on openURL:
    // occuring between ApplicationWillEnterForeground and ApplicationDidBecomeActive.
    
    // https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html#//apple_ref/doc/uid/TP40007072-CH6-SW8
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onEnterForeground:)
                                                 name:UIApplicationWillEnterForegroundNotification object:nil];
#endif
    
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
        NSError *adError = MSIDCreateError(ADAuthenticationErrorDomain, AD_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED, @"application did not receive response from broker.", nil, nil, nil, nil, nil);
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:adError];
        callback(result);
    }
}


@end
