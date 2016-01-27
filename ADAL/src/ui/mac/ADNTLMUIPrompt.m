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

#import "ADNTLMUIPrompt.h"
#import "ADCredentialCollectionController.h"

@interface ADNTLMUIPrompt ()
{
    
}

@end

@implementation ADNTLMUIPrompt

+ (void)presentPrompt:(void (^)(NSString * username, NSString * password))completionHandler
{
    NSAlert* alert = [NSAlert new];
    
    [alert setMessageText:NSLocalizedString(@"Enter your credentials", nil)];
    [alert addButtonWithTitle:NSLocalizedString(@"Login", nil)];
    [alert addButtonWithTitle:NSLocalizedString(@"Cancel", nil)];
    
    ADCredentialCollectionController* view = [ADCredentialCollectionController new];
    [view.usernameLabel setStringValue:NSLocalizedString(@"User Name", nil)];
    [view.passwordLabel setStringValue:NSLocalizedString(@"Password", nil)];
    [alert setAccessoryView:view.customView];
    
    [alert beginSheetModalForWindow:[NSApp keyWindow] completionHandler:^(NSModalResponse returnCode)
    {
        if (returnCode == 1)
        {
            NSString* username = [view.usernameField stringValue];
            NSString* password = [view.passwordField stringValue];
        
            completionHandler(username, password);
        }
        else
        {
            completionHandler(nil, nil);
        }
    }];
}

@end
