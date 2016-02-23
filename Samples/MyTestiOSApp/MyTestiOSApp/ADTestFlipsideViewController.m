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

#import "ADTestFlipsideViewController.h"
#import "ADTestInstance.h"

@interface ADTestFlipsideViewController ()

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

@implementation ADTestFlipsideViewController

- (void) updateControlValues
{
    ADTestInstance *instance = [ADTestInstance getInstance:nil];
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
    [[ADTestInstance getInstance:nil] restoreDefaults];
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
    
    [[ADTestInstance getInstance:nil] updateValues:updatedValues];
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
