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

#import "ADCredentialCollectionController.h"

// UI position values for the input dialog
const CGFloat USERNAME_LABEL_X = 7;
const CGFloat USERNAME_LABEL_Y = 36;
const CGFloat USERNAME_LABEL_WIDTH = 73;
const CGFloat USERNAME_LABEL_HEIGHT = 17;
const CGFloat USERNAME_FIELD_X = 85;
const CGFloat USERNAME_FIELD_Y = 36;
const CGFloat USERNAME_FIELD_WIDTH = 210;
const CGFloat USERNAME_FIELD_HEIGHT = 22;

const CGFloat PASSWORD_LABEL_X = 7;
const CGFloat PASSWORD_LABEL_Y = 6;
const CGFloat PASSWORD_LABEL_WIDTH = 72;
const CGFloat PASSWORD_LABEL_HEIGHT = 17;
const CGFloat PASSWORD_FIELD_X = 85;
const CGFloat PASSWORD_FIELD_Y = 6;
const CGFloat PASSWORD_FIELD_WIDTH = 210;
const CGFloat PASSWORD_FIELD_HEIGHT = 22;

const CGFloat CUSTOM_VIEW_X = 0;
const CGFloat CUSTOM_VIEW_Y = 0;
const CGFloat CUSTOM_VIEW_WIDTH = 306;
const CGFloat CUSTOM_VIEW_HEIGHT = 63;


@implementation ADCredentialCollectionController

@synthesize customView = _customView;
@synthesize usernameField = _usernameField;
@synthesize passwordField = _passwordField;
@synthesize usernameLabel = _usernameLabel;
@synthesize passwordLabel = _passwordLabel;

- (id)init
{
    self = [super init];
    if(self)
    {
        //Generate the NTLM input dialog by code for Mac
        //usename field
        _usernameLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(USERNAME_LABEL_X, USERNAME_LABEL_Y, USERNAME_LABEL_WIDTH, USERNAME_LABEL_HEIGHT)];
        [_usernameLabel setStringValue:NSLocalizedString(@"Username", nil)];
        [_usernameLabel setBezeled:NO];
        [_usernameLabel setDrawsBackground:NO];
        [_usernameLabel setEditable:NO];
        [_usernameLabel setSelectable:NO];
        
        _usernameField = [[NSTextField alloc] initWithFrame:NSMakeRect(USERNAME_FIELD_X, USERNAME_FIELD_Y, USERNAME_FIELD_WIDTH, USERNAME_FIELD_HEIGHT)];
        
        //password field
        _passwordLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(PASSWORD_LABEL_X, PASSWORD_LABEL_Y, PASSWORD_LABEL_WIDTH, PASSWORD_LABEL_HEIGHT)];
        [_passwordLabel setStringValue:NSLocalizedString(@"Password", nil)];
        [_passwordLabel setBezeled:NO];
        [_passwordLabel setDrawsBackground:NO];
        [_passwordLabel setEditable:NO];
        [_passwordLabel setSelectable:NO];
        
        _passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(PASSWORD_FIELD_X, PASSWORD_FIELD_Y, PASSWORD_FIELD_WIDTH, PASSWORD_FIELD_HEIGHT)];
        
        //add labels and fileds to view
        _customView = [[NSView alloc] initWithFrame:NSMakeRect(CUSTOM_VIEW_X, CUSTOM_VIEW_Y, CUSTOM_VIEW_WIDTH, CUSTOM_VIEW_HEIGHT)];
        [_customView addSubview:_usernameLabel];
        [_customView addSubview:_usernameField];
        [_customView addSubview:_passwordLabel];
        [_customView addSubview:_passwordField];
    }
    
    return self;
}

@end
