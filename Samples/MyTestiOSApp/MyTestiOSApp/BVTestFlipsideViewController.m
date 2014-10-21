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

#import "BVTestFlipsideViewController.h"
#import "BVTestInstance.h"

@interface BVTestFlipsideViewController ()

@property (weak, nonatomic) IBOutlet UITextField *authorityLabel;
@property (weak, nonatomic) IBOutlet UITextField *clientIdLabel;
@property (weak, nonatomic) IBOutlet UITextField *resourceLabel;
@property (weak, nonatomic) IBOutlet UITextField *redirectUriLabel;
@property (weak, nonatomic) IBOutlet UITextField *userIdLabel;
@property (weak, nonatomic) IBOutlet UITextField *passwordLabel;
@property (weak, nonatomic) IBOutlet UITextField *requestTimeoutLabel;
@property (weak, nonatomic) IBOutlet UITextField *extraQueryParameterLabel;
@property (weak, nonatomic) IBOutlet UISegmentedControl *validationSwitch;
@property (weak, nonatomic) IBOutlet UISegmentedControl *fullScreenSwitch;
@end

@implementation BVTestFlipsideViewController

- (void) updateControlValues
{
    BVTestInstance *instance = [BVTestInstance getInstance:nil];
    [_authorityLabel setText: [instance authority]];
    [_clientIdLabel setText: [instance clientId]];
    [_resourceLabel setText: [instance resource]];
    [_redirectUriLabel setText: [instance redirectUri]];
    [_userIdLabel setText: [instance userId]];
    [_passwordLabel setText: [instance password]];
    [_extraQueryParameterLabel setText: [instance extraQueryParameters]];
    [_requestTimeoutLabel setText:[NSString stringWithFormat:@"%d", [instance requestTimeout]]];
    [self configureControl:_validationSwitch forValue:[instance validateAuthority]];
    [self configureControl:_fullScreenSwitch forValue:[instance enableFullScreen]];
}


- (void)awakeFromNib
{
    self.preferredContentSize = CGSizeMake(320.0, 480.0);
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

- (IBAction)done:(id)sender
{
    [self.delegate flipsideViewControllerDidFinish:self];
}


- (IBAction)restoreDefaults:(id)sender
{
    [[BVTestInstance getInstance:nil] restoreDefaults];
    [self updateControlValues];
}


- (IBAction)save:(id)sender
{
    NSMutableDictionary* updatedValues = [NSMutableDictionary new];
    [updatedValues setObject:[_authorityLabel text] forKey:AUTHORITY];
    [updatedValues setObject:[_clientIdLabel text] forKey:CLIENT_ID];
    [updatedValues setObject:[_resourceLabel text] forKey:RESOURCE];
    [updatedValues setObject:[_redirectUriLabel text] forKey:REDIRECT_URI];
    [updatedValues setObject:[_userIdLabel text] forKey:USER_ID];
    [updatedValues setObject:[_passwordLabel text] forKey:PASSWORD];
    [updatedValues setObject:[_requestTimeoutLabel text] forKey:REQUEST_TIMEOUT];
    [updatedValues setObject:[_extraQueryParameterLabel text] forKey:EXTRA_QUERYPARAMETERS];
    [updatedValues setObject:[self isEnabled:_validationSwitch] forKey:SUPPORTS_VALIDATION];
    [updatedValues setObject:[self isEnabled:_fullScreenSwitch] forKey:ENABLE_FULLSCREEN];
    
    [[BVTestInstance getInstance:nil] updateValues:updatedValues];
    [self done:sender];
}

- (void) configureControl:(UISegmentedControl *)control forValue:(BOOL) enabled
{
    if(enabled){
        [control setSelectedSegmentIndex:1];
    }else
    {
        [control setSelectedSegmentIndex:0];
    }
}

- (NSNumber*) isEnabled:(UISegmentedControl *)control
{
    return [NSNumber numberWithBool:[control selectedSegmentIndex] != 0];
}

@end
