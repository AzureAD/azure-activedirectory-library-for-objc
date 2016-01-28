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

#import <Foundation/Foundation.h>

@interface ADCredentialCollectionController : NSObject {
    IBOutlet NSView *_customView;
    IBOutlet NSTextField *_usernameField;
    IBOutlet NSSecureTextField *_passwordField;
    IBOutlet NSTextField *_usernameLabel;
    IBOutlet NSTextField *_passwordLabel;
}

@property (strong) IBOutlet NSView *customView;
@property (strong) IBOutlet NSTextField *usernameField;
@property (strong) IBOutlet NSSecureTextField *passwordField;
@property (strong) IBOutlet NSTextField *usernameLabel;
@property (strong) IBOutlet NSTextField *passwordLabel;

@end
