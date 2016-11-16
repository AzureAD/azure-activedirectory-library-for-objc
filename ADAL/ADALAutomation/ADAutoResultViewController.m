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


#import "ADAutoResultViewController.h"
#import "ADAutoTextAndButtonView.h"

@interface ADAutoResultViewController ()
{
    ADAutoTextAndButtonView* _myView;
}

@end

@implementation ADAutoResultViewController
{
    NSString* _result;
}

- (id)initWithResultJson:(NSString*) result
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _result = result;
    
    return self;
}

- (void)loadView
{
    _myView = [[ADAutoTextAndButtonView alloc] initWithFrame:UIScreen.mainScreen.bounds];
    
    _myView.dataTextView.accessibilityIdentifier = @"resultInfo";
    
    [_myView.actionButton setTitle:@"Done" forState:UIControlStateNormal];
    [_myView.actionButton addTarget:self
                             action:@selector(done:)
                   forControlEvents:UIControlEventTouchUpInside];
    _myView.actionButton.accessibilityIdentifier = @"resultDone";
    
    self.view = _myView;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)done:(id)sender
{
    (void)sender;
    
    @synchronized (self)
    {
        [self dismissViewControllerAnimated:NO completion:^{
            
        }];
    }
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
