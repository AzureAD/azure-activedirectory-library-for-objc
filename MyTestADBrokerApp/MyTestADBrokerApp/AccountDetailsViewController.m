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

#import "AccountDetailsViewController.h"
#import <ADAuthenticationBroker/ADBrokerContext.h>
#import <ADAuthenticationBroker/ADBrokerConstants.h>
#import <ADAuthenticationBroker/NSString+ADBrokerHelperMethods.h>

@interface AccountDetailsViewController ()

@property (weak, nonatomic)   IBOutlet UIActivityIndicatorView *activityIndicator;
@property (weak, nonatomic) IBOutlet UISwitch* wpjEnabled;
@property (weak, nonatomic) IBOutlet UILabel* name;
@property (weak, nonatomic) IBOutlet UILabel* upn;

- (IBAction)deleteAccountPressed:(id)sender;

- (IBAction)wpjSwitchPressed:(id)sender;

@end

@implementation AccountDetailsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.name.text = [NSString stringWithFormat:@"%@ %@",
                      self.account.userInformation.givenName,
                      self.account.userInformation.familyName];
    self.upn.text = self.account.userInformation.userId;
    
    [_activityIndicator hidesWhenStopped];
    _activityIndicator.hidden = true;
    [_activityIndicator stopAnimating];
    // Do any additional setup after loading the view.
    RegistrationInformation* info = [ADBrokerContext getWorkPlaceJoinInformation];
    if(info)
    {
        self.wpjEnabled.enabled = [NSString adSame:self.account.userInformation.userId
                                          toString:info.userPrincipalName];
        [info releaseData];
        info = nil;
    }
    if(self.account.isWorkplaceJoined)
    {
        [self.wpjEnabled setOn:YES animated:YES];
    }
    else
    {
        [self.wpjEnabled setOn:NO animated:YES];
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)deleteAccountPressed:(id)sender
{
    UIAlertView * alert =[[UIAlertView alloc ] initWithTitle:@"Are you sure you want to delete the account?"
                                                     message:@""
                                                    delegate:self
                                           cancelButtonTitle:@"No"
                                           otherButtonTitles: nil];
    [alert addButtonWithTitle:@"Yes"];
    [alert show];

}

- (IBAction)wpjSwitchPressed:(id)sender
{
    ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:DEFAULT_AUTHORITY];
    if(!self.wpjEnabled.isOn)
    {
        //user wants to remove WPJ
        [ctx removeWorkPlaceJoinRegistration:^(NSError *error) {
            if(error)
            {
                UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to remove WPJ"
                                                                message:error.description
                                                               delegate:self
                                                      cancelButtonTitle:@"OK"
                                                      otherButtonTitles:nil];
                [alert show];
            } else
            {
                [self.navigationController popViewControllerAnimated:YES];
            }
        }];
    }
    else
    {
        //user wants to do WPJ
        [_activityIndicator startAnimating];
        [ctx doWorkPlaceJoinForUpn:self.account.userInformation.upn
                     onResultBlock:^(ADBrokerPRTCacheItem *item, NSError *error) {
                         [_activityIndicator stopAnimating];
                         if(error)
                         {
                             UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to WPJ"
                                                                             message:error.description
                                                                            delegate:self
                                                                   cancelButtonTitle:@"OK"
                                                                   otherButtonTitles:nil];
                             [alert show];
                         } else
                         {
                             [self.navigationController popViewControllerAnimated:YES];
                         }
                     }];
    }
}

- (void)alertView:(UIAlertView *)alertView didDismissWithButtonIndex:(NSInteger)buttonIndex
{
    if(buttonIndex == 1)
    {
        ADBrokerContext* ctx = [[ADBrokerContext alloc] initWithAuthority:DEFAULT_AUTHORITY];
        [ctx removeAccount:self.account.userInformation.upn onResultBlock:^(NSError *error) {
            if(error)
            {
                UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to remove account"
                                                             message:error.description
                                                            delegate:self
                                                   cancelButtonTitle:@"OK"
                                                   otherButtonTitles:nil];
                [alert show];
            }
            else
            {
                [self.navigationController popViewControllerAnimated:YES];
            }
        }];
    }
}

@end
