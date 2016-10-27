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

#import "ADAutoMainViewController.h"
#import "ADAutoParameterViewController.h"
#import "ADAutoInputViewController.h"
#import "ADAL_Internal.h"

@interface ADAutoMainViewController ()

@end

@implementation ADAutoMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)acquireToken:(id)sender
{
   /* ADAutoParameterViewController* paramController =
    [[ADAutoParameterViewController alloc] initWithParameters:@[@"userId", @"authority", @"clientId", @"resource", @"redirectUri"]
                                              completionBlock:^(NSDictionary<NSString *,NSString *> *parameters)*/
    ADAutoInputViewController* inputController =
    [[ADAutoInputViewController alloc] initWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
    {
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:YES
                                                      error:nil];
         
         [context acquireTokenWithResource:parameters[@"resource"]
                                  clientId:parameters[@"clientId"]
                               redirectUri:[NSURL URLWithString:parameters[@"redirectUri"]]
                           completionBlock:^(ADAuthenticationResult *result)
         {
             NSLog(@"Yay! %@", result);
         }];
     }];
    
    [self presentViewController:inputController animated:NO completion:^{
        NSLog(@"presented!");
    }];
}

@end
