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

#import "ADAuthenticationSettings.h"

@implementation ADAuthenticationSettings

@synthesize requestTimeOut = _requestTimeOut;
@synthesize expirationBuffer = _expirationBuffer;

#if !TARGET_OS_IPHONE
@synthesize defaultCacheDelegate = _defaultCacheDelegate;
#endif // !TARGET_OS_IPHONE

/*!
 An internal initializer used from the static creation function.
 */
-(id) initInternal
{
    self = [super init];
    if (self)
    {
        //Initialize the defaults here:
        self.requestTimeOut = 300;//in seconds.
        self.expirationBuffer = 300;//in seconds, ensures catching of clock differences between the server and the device
#if TARGET_OS_IPHONE
        self.enableFullScreen = YES;
        self.defaultKeychainGroup = @"com.microsoft.adalcache";
#endif
    }
    return self;
}

+(ADAuthenticationSettings*)sharedInstance
{
    /* Below is a standard objective C singleton pattern*/
    static ADAuthenticationSettings* instance;
    static dispatch_once_t onceToken;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[ADAuthenticationSettings alloc] initInternal];
        });
    }
    return instance;
}

@end

