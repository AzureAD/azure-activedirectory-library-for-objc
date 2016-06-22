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

static NSDictionary* s_profiles = nil;
static NSArray* s_profileTitles = nil;

@implementation ADTestAppSettings
{
    NSDictionary* _settings;
}

+ (void)initialize
{
    s_profiles =
    @{ @"Test App"    : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://graph.windows.net",
                           // NOTE: The settings below should come from your registered application on
                           //       the azure management portal.
                           @"clientId" : @"b92e0ba5-f86e-4411-8e18-6b5f928d968a",
                           @"redirectUri" : @"x-msauth-adaltestapp-210://com.microsoft.adal.2.1.0.TestApp",
                           },
       @"Office"      : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://api.office.com/discovery",
                           @"clientId" : @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                           @"redirectUri" : @"urn:ietf:wg:oauth:2.0:oob",
                           },
       @"OneDrive"    : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://api.office.com/discovery",
                           @"clientId" : @"af124e86-4e96-495a-b70a-90f90ab96707",
                           @"redirectUri" : @"ms-onedrive://com.microsoft.skydrive",
                           },
       };
    
    NSMutableArray* titles = [[NSMutableArray alloc] initWithCapacity:[s_profiles count]];
    
    for (NSString* profileTitle in s_profiles)
    {
        [titles addObject:profileTitle];
    }
    
    s_profileTitles = titles;
}

+ (NSDictionary*)profiles
{
    return s_profiles;
}

+ (NSArray*)profileTitles
{
    return s_profileTitles;
}

+ (ADTestAppSettings*)settings
{
    static dispatch_once_t s_settingsOnce;
    static ADTestAppSettings* s_settings = nil;
    
    dispatch_once(&s_settingsOnce,^{ s_settings = [ADTestAppSettings new]; });
    
    return s_settings;
}

+ (NSString*)currentProfileTitle
{
    NSString* currentProfile = [[NSUserDefaults standardUserDefaults] stringForKey:@"CurrentProfile"];
    
    return currentProfile ? currentProfile : @"Test App";
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSDictionary* profileDict = [s_profiles objectForKey:[ADTestAppSettings currentProfileTitle]];
    [self setFromDictionary:profileDict];
    
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
