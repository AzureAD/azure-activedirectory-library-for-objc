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

#if MS_REMOTE_PKEYAUTH_CALLBACK && TARGET_OS_SIMULATOR

#import "ADAuthenticationContext+RemoteDeviceIdentity.h"
#import "MSIDPKeyAuthHandler.h"

static ADRemotePkeyAuthResponseCallback s_ADRemotePkeyAuthResponseCallback = nil;
static BOOL s_isInMemoryTokenCacheEnabled = NO;

@implementation ADAuthenticationContext (RemoteDeviceIdentity)

+ (void)setRemotePkeyAuthCallback:(ADRemotePkeyAuthResponseCallback)callback
{
    @synchronized (self)
    {
        s_ADRemotePkeyAuthResponseCallback = [callback copy];
        
        [MSIDPKeyAuthHandler setRemotePkeyAuthCallback:^NSString * (NSString *challengeUrl) {
            
            @synchronized (self) //Guard against thread-unsafe callback
            {
                if (s_ADRemotePkeyAuthResponseCallback)
                {
                    return s_ADRemotePkeyAuthResponseCallback(challengeUrl);
                }
                else
                {
                    return nil;
                }
            }
        }];
        
    }
}

+ (void)setIsInMemoryTokenCacheEnabled:(BOOL)enabled
{
    s_isInMemoryTokenCacheEnabled = enabled;
}

+ (BOOL)isInMemoryTokenCacheEnabled
{
    return s_isInMemoryTokenCacheEnabled;
}
@end

#endif
