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
#import "ADAutoInputViewController.h"
#import "ADAutoResultViewController.h"
#import "ADAL_Internal.h"
#import "UIApplication+ADExtensions.h"

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
    ADAutoInputViewController* inputController = [ADAutoInputViewController new];
    
    [inputController startWithCompletionBlock:^(NSDictionary<NSString *,NSString *> *parameters)
     {
         ADAuthenticationContext* context =
         [[ADAuthenticationContext alloc] initWithAuthority:parameters[@"authority"]
                                          validateAuthority:YES
                                                      error:nil];
         
         [context acquireTokenWithResource:parameters[@"resource"]
                                  clientId:parameters[@"client_id"]
                               redirectUri:[NSURL URLWithString:parameters[@"redirect_uri"]]
                           completionBlock:^(ADAuthenticationResult *result)
          {
              [self dismissViewControllerAnimated:NO completion:^{
                  
                  [self displayAuthenticationResult:result];
              }];
          }];
     }];
}

-(void) displayAuthenticationResult:(ADAuthenticationResult*) result {
    ADAutoResultViewController* resultController = [[ADAutoResultViewController alloc] initWithResultJson:[self createJsonFromResult:result]];
    [[UIApplication adCurrentViewController] presentViewController:resultController animated:NO completion:^{
        NSLog(@"Result view controller loaded");
    }];
}

- (NSString*) createJsonFromResult:(ADAuthenticationResult*) result
{
    NSDictionary* resultDictionary = [NSDictionary new];
    [resultDictionary setValue:result.accessToken forKey:@"access_token"];
    [resultDictionary setValue:result.multiResourceRefreshToken forKey:@"mrrt";
     [resultDictionary setValue:result.correlationId forKey:@"correlation_id"];
     [resultDictionary setValue:result.error forKey:@"error"];
     [resultDictionary setValue:result.error. forKey:@"error"];
    
    return @"cancelled";
}

@end
