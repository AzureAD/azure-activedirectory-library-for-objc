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

#import "AppSettingsViewController.h"
#import <workplacejoinAPI/WorkplaceJoin.h>
#import <ADAuthenticationBroker/ADBrokerSettings.h>

@interface AppSettingsViewController ()

@end

@implementation AppSettingsViewController

WPJEnvironment env = PROD;

@synthesize picker, pickerData;

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    // Do any additional setup after loading the view, typically from a nib.
    NSArray *array = [[NSArray alloc] initWithObjects:@"PROD", @"PPE", @"INT", nil ];
    self.pickerData = array;
 
    
    [picker selectRow:[self mapEnvironmentToIntValue:[ADBrokerSettings sharedInstance].wpjEnvironment]
          inComponent:0
             animated:YES];
}

-(NSInteger) numberOfComponentsInPickerView: (UIPickerView*) pickerView
{
    return 1;
}

-(NSInteger) pickerView: (UIPickerView *) pickerView numberOfRowsInComponent:(NSInteger)component
{
    return [pickerData count];
}

-(NSString*) pickerView: (UIPickerView *) pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component
{
    return [self.pickerData objectAtIndex:row];
}

-(void) pickerView: (UIPickerView *) pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component
{
    int select = (int)row;
    switch (select) {
        case 0:
            env = PROD;
            break;
            
        case 1:
            env = PPE;
            break;
            
        case 2:
            env = INT;
            break;
            
        default:
            break;
    }
}

- (int) mapEnvironmentToIntValue:(WPJEnvironment) environment
{
    int value = 0;
    switch (environment) {
        case PROD:
            value = 0;
            break;
        case PPE:
            value = 1;
            break;
        case INT:
            value = 2;
            break;
        default:
            break;
    }
    
    return value;
}

- (IBAction)savePressed:(id)sender
{
    [ADBrokerSettings sharedInstance].wpjEnvironment = env;
    [self.navigationController popViewControllerAnimated:YES];
}


@end
