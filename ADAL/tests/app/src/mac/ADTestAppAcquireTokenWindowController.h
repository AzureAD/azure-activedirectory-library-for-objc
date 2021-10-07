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

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import "ADAL_Internal.h"
#import "ADALUserIdentifier.h"

@interface ADTestAppAcquireTokenWindowController : NSWindowController
{
    IBOutlet NSView* _authView;
    
    IBOutlet NSView *_contentWebView;
    IBOutlet NSView* _acquireSettingsView;
    IBOutlet NSTextField* _userIdField;
    IBOutlet NSTextView* _resultView;
    IBOutlet NSSegmentedControl* _validateAuthority;
    IBOutlet NSSegmentedControl* _webViewType;
    IBOutlet NSSegmentedControl* _capabilitiesControl;
    
    IBOutlet NSPopUpButton* _profiles;
    
    IBOutlet NSTextField* _authority;
    IBOutlet NSTextField* _clientId;
    IBOutlet NSTextField* _redirectUri;
    IBOutlet NSTextField* _resource;
    
    IBOutlet NSTextField* _extraQueryParamsField;
    IBOutlet NSTextField* _claimsField;
    
    WKWebView* _webview;
    
    ADALUserIdentifierType _idType;
    ADPromptBehavior _promptBehavior;
    
    BOOL _userIdEdited;
}

+ (void)showWindow;

@end
