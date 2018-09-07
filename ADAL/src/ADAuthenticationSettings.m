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

#import "ADAuthenticationSettings.h"

#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache.h"
#else
#import "ADTokenCache+Internal.h"
#endif // TARGET_OS_IPHONE


@implementation ADAuthenticationSettings

@synthesize requestTimeOut = _requestTimeOut;
@synthesize expirationBuffer = _expirationBuffer;

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
        
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        self.enableFullScreen = YES;
#pragma clang diagnostic pop
        self.webviewPresentationStyle = UIModalPresentationFullScreen;
#endif
    }
    return self;
}

#if TARGET_OS_IPHONE
- (BOOL)enableFullScreen
{
    return _webviewPresentationStyle == UIModalPresentationFullScreen;
}

- (void)setEnableFullScreen:(BOOL)enableFullScreen
{
    if (enableFullScreen)
    {
        _webviewPresentationStyle = UIModalPresentationFullScreen;
    }
    else
    {
        _webviewPresentationStyle = UIModalPresentationFormSheet;
    }
}
#endif

+(ADAuthenticationSettings*)sharedInstance
{
    /* Below is a standard objective C singleton pattern*/
    static ADAuthenticationSettings* instance = nil;
    static dispatch_once_t onceToken;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[ADAuthenticationSettings alloc] initInternal];
        });
    }
    return instance;
}

#if TARGET_OS_IPHONE
- (NSString*)defaultKeychainGroup
{
    return [ADKeychainTokenCache defaultKeychainGroup];
}

- (void)setDefaultKeychainGroup:(NSString*)keychainGroup
{
    [ADKeychainTokenCache setDefaultKeychainGroup:keychainGroup];
}

#elif !TARGET_OS_IPHONE
- (id<ADTokenCacheDelegate>)defaultStorageDelegate
{
    return [[ADTokenCache defaultCache] delegate];
}

- (void)setDefaultStorageDelegate:(id<ADTokenCacheDelegate>)defaultStorageDelegate
{
    [[ADTokenCache defaultCache] setDelegate:defaultStorageDelegate];
}
#endif

@end

