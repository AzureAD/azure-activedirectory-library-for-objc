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

#import "ADTestAppSettingsViewController.h"
#import "ADTestAppProfileViewController.h"
#import "ADTestAppSettings.h"

// Internal ADAL headers
#import "ADWorkPlaceJoinUtil.h"
#import "ADKeychainUtil.h"
#import "ADRegistrationInformation.h"


@interface ADTestAppSettingsViewController ()

@end

@implementation ADTestAppSettingsViewController
{
    IBOutlet UIButton* _profile;
    IBOutlet UIButton* _authority;
    IBOutlet UILabel* _clientId;
    IBOutlet UILabel* _redirectUri;
    IBOutlet UIButton* _resource;
    IBOutlet UILabel* _keychainId;
    IBOutlet UILabel* _workplaceJoin;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    self.navigationController.navigationBarHidden = YES;
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Settings"
                                                    image:[UIImage imageNamed:@"Settings"]
                                                      tag:0];
    
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    NSString* teamId = [ADKeychainUtil keychainTeamId:nil];
    
    [_keychainId setText: teamId ? teamId : @"<No Team ID>" ];
    
    [self refreshProfileSettings];
}

- (void)viewWillAppear:(BOOL)animated
{
    ADRegistrationInformation* regInfo =
    [ADWorkPlaceJoinUtil getRegistrationInformation:nil error:nil];
    
    NSString* wpjLabel = @"No WPJ Registration Found";
    
    if (regInfo.userPrincipalName)
    {
        wpjLabel = regInfo.userPrincipalName;
    }
    else if (regInfo)
    {
        wpjLabel = @"WPJ Registration Found";
    }
    
    [_workplaceJoin setText:wpjLabel];
    
    [self refreshProfileSettings];
}

- (IBAction)gotoProfile:(id)sender
{
    [self.navigationController pushViewController:[ADTestAppProfileViewController sharedProfileViewController] animated:YES];
}

- (void)refreshProfileSettings
{
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    [_authority setTitle:settings.authority forState:UIControlStateNormal];
    [_clientId setText:settings.clientId];
    [_redirectUri setText:settings.redirectUri.absoluteString];
    [_resource setTitle:settings.resource forState:UIControlStateNormal];
    [_profile setTitle:[ADTestAppSettings currentProfileTitle] forState:UIControlStateNormal];
}

@end
