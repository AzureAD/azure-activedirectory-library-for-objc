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

#import "ADTestAppSettings.h"

NSString* ADTestAppCacheChangeNotification = @"ADTestAppCacheChangeNotification";

@implementation ADTestAppSettings
{
    NSDictionary* _settings;
}

+ (ADTestAppSettings*)settings
{
    static dispatch_once_t s_settingsOnce;
    static ADTestAppSettings* s_settings = nil;
    
    dispatch_once(&s_settingsOnce,^{ s_settings = [ADTestAppSettings new]; });
    
    return s_settings;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSDictionary* defaultSettings =
    @{ @"authority" : @"https://login.microsoftonline.com/common",
       @"resource" : @"https://graph.windows.net",
       // NOTE: The settings below should come from your registered application on
       //       the azure management portal.
       @"clientId" : @"b92e0ba5-f86e-4411-8e18-6b5f928d968a",
       @"redirectUri" : @"x-msauth-adaltestapp-210://com.microsoft.adal.2.1.0.TestApp",
       };
    
    [self setFromDictionary:defaultSettings];
    
    return self;
}

- (void)setFromDictionary:(NSDictionary *)settings
{
    self.authority = [settings objectForKey:@"authority"];
    self.clientId = [settings objectForKey:@"clientId"];
    self.redirectUri = [NSURL URLWithString:[settings objectForKey:@"redirectUri"]];
    self.resource = [settings objectForKey:@"resource"];
}

@end
