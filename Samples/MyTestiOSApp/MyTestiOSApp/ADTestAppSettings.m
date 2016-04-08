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
    
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    
    NSDictionary* defaultValues = @{ @"authority" : @"https://login.microsoftonline.com/common",
                                     @"clientId" : @"e3786e2a-0dcb-449a-8eba-b4042c9bec01",
                                     @"resource" : @"https://graph.windows.net",
                                     @"redirectUri" : @"MyTestiOSApp://com.MSOpenTech.MyTestiOSApp" };
    
    
    [defaults registerDefaults:defaultValues];
    
    
    self.authority = [defaults stringForKey:@"authority"];
    self.clientId = [defaults stringForKey:@"clientId"];
    self.redirectUri = [NSURL URLWithString:[defaults stringForKey:@"redirectUri"]];
    self.resource = [defaults stringForKey:@"resource"];
    
    return self;
}

@end
