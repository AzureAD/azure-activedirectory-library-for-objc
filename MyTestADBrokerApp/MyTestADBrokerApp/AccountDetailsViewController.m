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

#import <ADAuthenticationBroker/ADBrokerContext.h>
#import <ADAuthenticationBroker/ADBrokerConstants.h>
#import <ADAuthenticationBroker/ADBrokerUserAccount.h>
#import "AccountDetailsViewController.h"

@interface AccountDetailsViewController ()

@property (weak, nonatomic) IBOutlet UISwitch* wpjEnabled;
@property (weak, nonatomic) IBOutlet UILabel* name;
@property (weak, nonatomic) IBOutlet UILabel* upn;
@property (weak, nonatomic) IBOutlet UIButton* prtButton;
@property (weak, nonatomic) IBOutlet UIButton* deletePrtButton;

@property (weak, nonatomic) IBOutlet UIButton* getATFromPrtButton;
@property (weak, nonatomic) IBOutlet UITextField* clientId;
@property (weak, nonatomic) IBOutlet UITextField* redirectUri;
@property (weak, nonatomic) IBOutlet UITextField* resource;

- (IBAction)deleteAccountPressed:(id)sender;
- (IBAction)wpjSwitchPressed:(id)sender;
- (IBAction)getPRTPressed:(id)sender;
- (IBAction)deletePRTPressed:(id)sender;
- (IBAction)getATFromPRTPressed:(id)sender;

@end

@implementation AccountDetailsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.name.text = [NSString stringWithFormat:@"%@ %@",
                      self.account.userInformation.givenName,
                      self.account.userInformation.familyName];
    self.upn.text = self.account.userInformation.userId;
    
    // Do any additional setup after loading the view.
    RegistrationInformation* info = [ADBrokerContext getWorkPlaceJoinInformation];
    if(info)
    {
        self.wpjEnabled.enabled = [self.account.userInformation.userId isEqualToString:
                                   info.userPrincipalName];
        [info releaseData];
        info = nil;
    }
    
    
    [self.deletePrtButton setEnabled:self.account.isWorkplaceJoined];
    [self.prtButton setEnabled:self.account.isWorkplaceJoined];
    [self.getATFromPrtButton setEnabled:self.account.isWorkplaceJoined];

    if(self.account.isWorkplaceJoined)
    {
        [self.wpjEnabled setOn:YES animated:YES];    }
    else
    {
        [self.wpjEnabled setOn:NO animated:YES];
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)deletePRTPressed:(id)sender
{
    ADBrokerPRTContext* ctx = [[ADBrokerPRTContext alloc] initWithUpn:self.upn.text
                                                        correlationId:[NSUUID UUID]
                                                                error:nil];
    [ctx deletePRT];
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

- (IBAction)getPRTPressed:(id)sender
{
    ADBrokerPRTContext* ctx = [[ADBrokerPRTContext alloc] initWithUpn:self.account.userInformation.upn correlationId:[NSUUID UUID] error:nil];
    [ctx acquirePRTForUPN:^(ADBrokerPRTCacheItem *item, NSError *error) {
        if(error)
        {                UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to get PRT"
                                                                         message:error.description
                                                                        delegate:self
                                                               cancelButtonTitle:@"OK"
                                                               otherButtonTitles:nil];
            [alert show];
        }
    }];
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
        [ctx doWorkPlaceJoinForUpn:self.account.userInformation.upn
                     onResultBlock:^(ADBrokerPRTCacheItem *item, NSError *error) {
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


- (IBAction)getATFromPRTPressed:(id)sender
{

    ADBrokerContext*ctx = [[ADBrokerContext alloc] initWithAuthority:DEFAULT_AUTHORITY];
    [ctx setCorrelationId:[NSUUID UUID]];
    [ctx acquireAccount:self.account.userInformation.upn
               clientId:self.clientId.text
               resource:self.resource.text
            redirectUri:self.redirectUri.text
        completionBlock:^(ADAuthenticationResult *result) {
            if(result.status != AD_SUCCEEDED)
            {
                UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to get Token"
                                                                message:result.error.description
                                                               delegate:self
                                                      cancelButtonTitle:@"OK"
                                                      otherButtonTitles:nil];
                [alert show];
            }
            else
            {
                //do something
            }
        }];
    
//    ADBrokerPRTContext* ctx = [[ADBrokerPRTContext alloc] initWithUpn:self.account.userInformation.upn correlationId:[NSUUID UUID] error:nil];
//    [ctx acquireTokenUsingPRTForResource:@"https://graph.windows.net"
//                                clientId:self.clientId.text
//                             redirectUri:self.redirectUri.text
//                                  appKey:DEFAULT_GUID_FOR_NIL
//                         completionBlock:^(ADAuthenticationResult *result) {
//                             if(result.status != AD_SUCCEEDED)
//                             {
//                                 UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Failed to get Token"
//                                                                                 message:result.error.description
//                                                                                delegate:self
//                                                                       cancelButtonTitle:@"OK"
//                                                                       otherButtonTitles:nil];
//                                 [alert show];
//                             }
//                             else
//                             {
//                                 //do somethin
//                             }
//                         }];
}

@end
