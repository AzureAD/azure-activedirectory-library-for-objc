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

#import "ADTestAppSettingsViewController.h"
#import "ADTestAppSettings.h"

#import <objc/runtime.h>

@interface ADTestAppSettingsViewController ()

@property (weak, nonatomic) IBOutlet UITextField *authorityLabel;
@property (weak, nonatomic) IBOutlet UITextField *clientIdLabel;
@property (weak, nonatomic) IBOutlet UITextField *redirectUriLabel;
@property (weak, nonatomic) IBOutlet UITextField *requestTimeoutLabel;
@property (weak, nonatomic) IBOutlet UITextField *extraQueryParameterLabel;
@property (weak, nonatomic) IBOutlet UISwitch *validationSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *fullScreenSwitch;
@end

@implementation ADTestAppSettingsViewController

- (void)updateControlValues
{
    NSArray* controls = @[ _authorityLabel, _clientIdLabel, _redirectUriLabel, _requestTimeoutLabel,
                           _extraQueryParameterLabel, _validationSwitch, _fullScreenSwitch];
    
    for (UIControl* control in controls)
    {
        [[ADUserDefaultsSettings defaultSettings] populateControl:control];
    }
}


- (void)awakeFromNib
{
    [super awakeFromNib];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [self updateControlValues];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - Actions

- (IBAction)restoreDefaults:(id)sender
{
    [[ADUserDefaultsSettings defaultSettings] reset];
    [self updateControlValues];
}

- (IBAction)valueChanged:(id)control
{
    NSString* settingKey = [control valueForKey:@"settingKey"];
    NSAssert(settingKey, @"You must set a settingKey user-defined key value in IB for this control!");
    if ([control isKindOfClass:[UITextField class]])
    {
        NSString* val = [(UITextField*)control text];
        [[ADUserDefaultsSettings defaultSettings] setValue:val forKey:settingKey];
    }
    else if ([control isKindOfClass:[UISwitch class]])
    {
        BOOL val = [(UISwitch*)control isOn];
        [[ADUserDefaultsSettings defaultSettings] setValue:[NSNumber numberWithBool:val] forKey:settingKey];
    }
    else
    {
        NSAssert(nil, @"unrecognized type %@", NSStringFromClass([control class]));
    }
}

@end
