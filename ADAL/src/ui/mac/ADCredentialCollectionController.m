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

@implementation ADCredentialCollectionController

@synthesize customView = _customView;
@synthesize usernameField = _usernameField;
@synthesize passwordField = _passwordField;
@synthesize usernameLabel = _usernameLabel;
@synthesize passwordLabel = _passwordLabel;

-(id) init
{
    self = [super init];
    if(self)
    {
        //Generate the NTLM input dialog by code for Mac
        //usename field
        _usernameLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(7, 36, 73, 17)];
        [_usernameLabel setStringValue:@"User Name"];
        [_usernameLabel setBezeled:NO];
        [_usernameLabel setDrawsBackground:NO];
        [_usernameLabel setEditable:NO];
        [_usernameLabel setSelectable:NO];
        
        _usernameField = [[NSTextField alloc] initWithFrame:NSMakeRect(85, 36,210, 22)];
        
        //password field
        _passwordLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(7, 6, 72, 17)];
        [_passwordLabel setStringValue:@"Password"];
        [_passwordLabel setBezeled:NO];
        [_passwordLabel setDrawsBackground:NO];
        [_passwordLabel setEditable:NO];
        [_passwordLabel setSelectable:NO];
        
        _passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(85, 6,210, 22)];
        
        //add labels and fileds to view
        _customView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 306, 63)];
        [_customView addSubview:_usernameLabel];
        [_customView addSubview:_usernameField];
        [_customView addSubview:_passwordLabel];
        [_customView addSubview:_passwordField];
    }
    
    return self;
}

@end
