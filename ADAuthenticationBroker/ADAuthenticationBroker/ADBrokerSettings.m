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

#import "ADBrokerSettings.h"
#import "ADBrokerKeychainTokenCacheStore.h"

@implementation ADBrokerSettings

/*!
 An internal initializer used from the static creation function.
 */
-(id) initInternal
{
    self = [super init];
    if (self)
    {
        //Initialize the defaults here:
        self.prtRequestWaitInSeconds = 5;
        self.wpjEnvironment = PROD;
        _defaultCacheInstance = [ADBrokerKeychainTokenCacheStore new];
    }
    return self;
}

+(ADBrokerSettings*) sharedInstance
{
    /* Below is a standard objective C singleton pattern*/
    static ADBrokerSettings* instance;
    static dispatch_once_t onceToken;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[ADBrokerSettings alloc] initInternal];
        });
    }
    
    return instance;
}


-(NSString*) authority
{
    {
        NSString *authEndpoint = nil;
        switch (self.wpjEnvironment)
        {
                
            case NONE:
            case PROD:
                authEndpoint = @"https://login.windows.net/common";
                break;
                
            case PPE:
                authEndpoint = @"https://login.windows-ppe.net/common";
                break;
                
            case INT:
                authEndpoint = @"https://login.windows-int.net/common";
                break;
        }
        
        return authEndpoint;
    }
}

@end