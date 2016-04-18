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
#import "ADTestAppSettings.h"

// Internal ADAL headers
#import "ADWorkPlaceJoin.h"
#import "ADWorkPlaceJoinUtil.h"


@interface ADTestAppSettingsViewController ()

@end

@implementation ADTestAppSettingsViewController
{
    IBOutlet UIButton* _authority;
    IBOutlet UILabel* _clientId;
    IBOutlet UILabel* _redirectUri;
    IBOutlet UIButton* _resource;
    IBOutlet UILabel* _keychainId;
    IBOutlet UILabel* _workplaceJoin;
}

- (id)init
{
    if (!(self = [super initWithNibName:@"ADTestAppSettingsView" bundle:nil]))
    {
        return nil;
    }
    
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Settings"
                                                    image:[UIImage imageNamed:@"Settings"]
                                                      tag:0];
    
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view from its nib.
    
    ADTestAppSettings* settings = [ADTestAppSettings settings];
    
    [_authority setTitle:settings.authority forState:UIControlStateNormal];
    [_clientId setText:settings.clientId];
    [_redirectUri setText:settings.redirectUri.absoluteString];
    [_resource setTitle:settings.resource forState:UIControlStateNormal];
    [_keychainId setText:[[ADWorkPlaceJoinUtil WorkPlaceJoinUtilManager]  getApplicationIdentifierPrefix]];
}

- (void)viewWillAppear:(BOOL)animated
{
    ADRegistrationInformation* regInfo =
    [[ADWorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation];
    
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
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
