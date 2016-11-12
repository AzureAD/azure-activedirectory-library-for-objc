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

@interface ADAutoResultViewController ()

@end

@implementation ADAutoResultViewController
{
    NSString* _result;
    UITextView * _outputTextview;
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
    UIView* rootView = [[UIView alloc] initWithFrame:UIScreen.mainScreen.bounds];
    rootView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    rootView.translatesAutoresizingMaskIntoConstraints = YES;
    rootView.autoresizesSubviews = NO;
    rootView.backgroundColor = UIColor.whiteColor;
    self.view = rootView;
    
    UITextView* textView = [[UITextView alloc] init];
    textView.autocorrectionType = UITextAutocorrectionTypeNo;
    textView.accessibilityIdentifier = @"resultInfo";
    textView.translatesAutoresizingMaskIntoConstraints = NO;
    textView.editable = NO;
    textView.scrollEnabled = YES;
    textView.text = _result;
    textView.layer.cornerRadius = 8.0;
    textView.layer.borderWidth = 1.0;
    textView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    
    _outputTextview = textView;
    
    UIButton* doneButton = [[UIButton alloc] init];
    [doneButton setTitle:@"Done" forState:UIControlStateNormal];
    [doneButton addTarget:self
                 action:@selector(done:)
       forControlEvents:UIControlEventTouchUpInside];
    doneButton.backgroundColor = UIColor.greenColor;
    doneButton.titleLabel.textColor = UIColor.whiteColor;
    doneButton.translatesAutoresizingMaskIntoConstraints = NO;
    doneButton.accessibilityIdentifier = @"resultDone";
    
    [rootView addSubview:textView];
    [rootView addSubview:doneButton];
    
    UILayoutGuide* margins = self.view.layoutMarginsGuide;
    [textView.topAnchor constraintEqualToAnchor:self.topLayoutGuide.bottomAnchor constant:8.0].active = YES;
    [textView.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
    [textView.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor].active = YES;
    [textView.bottomAnchor constraintEqualToAnchor:doneButton.topAnchor constant:-8.0].active = YES;
    [doneButton.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
    [doneButton.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor].active = YES;
    [doneButton.heightAnchor constraintEqualToConstant:20.0];
    [doneButton.bottomAnchor constraintEqualToAnchor:self.bottomLayoutGuide.topAnchor constant:-8.0].active = YES;
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
