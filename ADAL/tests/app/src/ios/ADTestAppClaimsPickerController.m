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

#import "ADTestAppClaimsPickerController.h"

@interface ADTestAppClaimsPickerController () <UIPickerViewDataSource, UIPickerViewDelegate>

@end

@implementation ADTestAppClaimsPickerController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    UILayoutGuide *margins = self.view.layoutMarginsGuide;
    
    self.claimsPickerView = [[UIPickerView alloc]initWithFrame:CGRectZero];
    self.claimsPickerView.dataSource = self;
    self.claimsPickerView.delegate = self;
    [self.claimsPickerView selectRow:1 inComponent:0 animated:YES];
    [self.view addSubview:self.claimsPickerView];
    self.claimsPickerView.translatesAutoresizingMaskIntoConstraints = NO;
    UIView *view = self.claimsPickerView;
    [self.view addConstraints:[NSLayoutConstraint
                               constraintsWithVisualFormat:@"V:|[view]|"
                               options:0l
                               metrics:nil
                               views:NSDictionaryOfVariableBindings(view)]];
    
    [self.view addConstraints:[NSLayoutConstraint
                               constraintsWithVisualFormat:@"H:|[view]|"
                               options:0l
                               metrics:nil
                               views:NSDictionaryOfVariableBindings(view)]];
    
    
    UIButton *cancelButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.view addSubview:cancelButton];
    cancelButton.translatesAutoresizingMaskIntoConstraints = NO;
    [cancelButton.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor constant:0].active = YES;
    [cancelButton.topAnchor constraintEqualToAnchor:margins.topAnchor constant:0].active = YES;
    [cancelButton.widthAnchor constraintEqualToConstant:50].active = YES;
    [cancelButton.heightAnchor constraintEqualToConstant:40].active = YES;
    [cancelButton setTitle:@"Cancel" forState:UIControlStateNormal];
    [cancelButton addTarget:self action:@selector(onClaimsCancelButtonTapped:) forControlEvents:UIControlEventTouchUpInside];

    UIButton *clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.view addSubview:clearButton];
    clearButton.translatesAutoresizingMaskIntoConstraints = NO;
    [clearButton.topAnchor constraintEqualToAnchor:margins.topAnchor constant:0].active = YES;
    [clearButton.centerXAnchor constraintEqualToAnchor:margins.centerXAnchor constant:0].active = YES;
    [clearButton.widthAnchor constraintEqualToConstant:50].active = YES;
    [clearButton.heightAnchor constraintEqualToConstant:40].active = YES;
    [clearButton setTitle:@"Clear" forState:UIControlStateNormal];
    [clearButton addTarget:self action:@selector(onClaimsClearButtonTapped:) forControlEvents:UIControlEventTouchUpInside];

    UIButton *doneButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.view addSubview:doneButton];
    doneButton.translatesAutoresizingMaskIntoConstraints = NO;
    [doneButton.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor constant:0].active = YES;
    [doneButton.topAnchor constraintEqualToAnchor:margins.topAnchor constant:0].active = YES;
    [doneButton.widthAnchor constraintEqualToConstant:50].active = YES;
    [doneButton.heightAnchor constraintEqualToConstant:40].active = YES;
    [doneButton setTitle:@"Select" forState:UIControlStateNormal];
    [doneButton addTarget:self action:@selector(onClaimsDoneButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
}

#pragma mark - Public

- (NSDictionary *)claims
{
    if (!_claims)
    {
        _claims = @{};
    }
    
    return _claims;
}

#pragma mark - IBAction

- (IBAction)onClaimsCancelButtonTapped:(id)sender
{
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)onClaimsClearButtonTapped:(id)sender
{
    self.claimsTextField.text = nil;
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)onClaimsDoneButtonTapped:(id)sender
{
    NSInteger row = [self.claimsPickerView selectedRowInComponent:0];
    NSString *claim = self.claims.allValues[row];
    
    self.claimsTextField.text = claim;
    
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - UIPickerViewDataSource

- (NSInteger)numberOfComponentsInPickerView:(UIPickerView *)pickerView
{
    return 1;
}

- (NSInteger)pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component
{
    return self.claims.count;
}

#pragma mark - UIPickerViewDelegate

- (NSString *)pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component
{
    return self.claims.allKeys[row];
}

@end
