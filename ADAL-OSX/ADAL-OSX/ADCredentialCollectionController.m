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

#import "ADCredentialCollectionController.h"

@implementation ADCredentialCollectionController

@synthesize customView = _customView;
@synthesize usernameField = _usernameField;
@synthesize passwordField = _passwordField;

-(id) init
{
    self = [super init];
    BOOL loaded = NO;
    if(self)
    {
        loaded = [NSBundle loadNibNamed:@"ADCredentialViewController" owner:self];
//        loaded = [[NSBundle mainBundle] loadNibNamed:@"ADCredentialViewController" owner:self topLevelObjects:nil];
    }
    SAFE_ARC_RETAIN(_customView);
    SAFE_ARC_RETAIN(_usernameField);
    SAFE_ARC_RETAIN(_passwordField);
    return self;
}

-(void)dealloc
{
    [super dealloc];
    SAFE_ARC_RELEASE(_customView);
    SAFE_ARC_RELEASE(_usernameField);
    SAFE_ARC_RELEASE(_passwordField);
    _customView = nil;
    _usernameField = nil;
    _passwordField = nil;
}

@end
