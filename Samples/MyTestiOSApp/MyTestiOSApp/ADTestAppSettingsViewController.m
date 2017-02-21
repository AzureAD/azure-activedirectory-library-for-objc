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

#import "ADTestAppSettingsViewController.h"
#import "ADTestAppProfileViewController.h"
#import "ADTestAppSettings.h"

// Internal ADAL headers
#import "ADWorkPlaceJoinUtil.h"
#import "ADKeychainUtil.h"
#import "ADRegistrationInformation.h"

static NSArray* s_profileRows = nil;
static NSArray* s_deviceRows = nil;

@interface ADTestAppSettingsRow : NSObject

@property (nonatomic, retain) NSString* title;
@property (nonatomic, copy) NSString*(^valueBlock)();
@property (nonatomic, copy) void(^action)();

+ (ADTestAppSettingsRow*)rowWithTitle:(NSString *)title;

@end

@implementation ADTestAppSettingsRow

+ (ADTestAppSettingsRow*)rowWithTitle:(NSString *)title
{
    ADTestAppSettingsRow* row = [ADTestAppSettingsRow new];
    row.title = title;
    return row;
}

+ (ADTestAppSettingsRow*)rowWithTitle:(NSString *)title
                                value:(NSString*(^)())value
{
    ADTestAppSettingsRow* row = [ADTestAppSettingsRow new];
    row.title = title;
    row.valueBlock = value;
    return row;
}

@end

@interface ADTestAppSettingsViewController () <UITableViewDelegate, UITableViewDataSource>

@end

@implementation ADTestAppSettingsViewController
{
    UITableView* _tableView;
    
    NSArray* _profileRows;
    NSArray* _deviceRows;
    
    NSString* _keychainId;
    NSString* _wpjState;
}

#define SETTING_ROW(_SETTING) \
    ADTestAppSettingsRow* _SETTING = [ADTestAppSettingsRow rowWithTitle:@#_SETTING]; \
    _SETTING.valueBlock = ^NSString *{ return ADTestAppSettings.settings._SETTING; }

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Settings"
                                                    image:[UIImage imageNamed:@"Settings"]
                                                      tag:0];
    
    
    NSString* teamId = [ADKeychainUtil keychainTeamId:nil];
    _keychainId = teamId ? teamId : @"<No Team ID>";
    
    ADTestAppSettingsRow* profileRow = [ADTestAppSettingsRow rowWithTitle:@"profile"];
    profileRow.valueBlock = ^NSString *{ return ADTestAppSettings.currentProfileTitle; };
    profileRow.action = ^{ [self gotoProfile:nil]; };
    SETTING_ROW(authority);
    SETTING_ROW(clientId);
    SETTING_ROW(resource);
    ADTestAppSettingsRow* redirectUri = [ADTestAppSettingsRow rowWithTitle:@"redirectUri"];
    redirectUri.valueBlock = ^NSString *{ return [ADTestAppSettings.settings.redirectUri absoluteString]; };
    
    _profileRows = @[ profileRow, authority, clientId, redirectUri, resource];
    
    
    
    _deviceRows = @[ [ADTestAppSettingsRow rowWithTitle:@"TeamID" value:^NSString *{ return _keychainId; }],
                     [ADTestAppSettingsRow rowWithTitle:@"WPJ State" value:^NSString *{ return _wpjState; }]];
    
    return self;
}

- (void)loadView
{
    CGRect screenFrame = UIScreen.mainScreen.bounds;
    _tableView = [[UITableView alloc] initWithFrame:screenFrame];
    _tableView.delegate = self;
    _tableView.dataSource = self;
    _tableView.allowsSelection = YES;
    
    self.view = _tableView;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
}



- (void)viewWillAppear:(BOOL)animated
{
    ADRegistrationInformation* regInfo =
    [ADWorkPlaceJoinUtil getRegistrationInformation:nil error:nil];
    
    NSString* wpjLabel = @"No WPJ Registration Found";
    
    if (regInfo)
    {
        wpjLabel = @"WPJ Registration Found";
    }
    
    _wpjState = wpjLabel;
    
    self.navigationController.navigationBarHidden = YES;
    
    [_tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    if (section == 0)
        return _profileRows.count;
    if (section == 1)
        return _deviceRows.count;
    
    return 0;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView;
{
    return 2;
}

- (nullable NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (section == 0)
        return @"Authentication Settings";
    if (section == 1)
        return @"Device State";
    
    return nil;
}


- (ADTestAppSettingsRow*)rowForIndexPath:(NSIndexPath *)indexPath
{
    NSInteger section = [indexPath indexAtPosition:0];
    NSInteger row = [indexPath indexAtPosition:1];
    
    if (section == 0)
    {
        return _profileRows[row];
    }
    
    if (section == 1)
    {
        return _deviceRows[row];
    }
    
    return nil;
}

- (nullable NSIndexPath *)tableView:(UITableView *)tableView willSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    ADTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    if (!row.action)
        return nil;
    
    row.action();
    return nil;
}

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"settingsCell"];
    if (!cell)
    {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"settingsCell"];
    }
    
    ADTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    cell.textLabel.text = row.title;
    cell.detailTextLabel.text = row.valueBlock();
    
    if (row.action)
    {
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    
    return cell;
}

- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath
{
    ADTestAppSettingsRow* row = [self rowForIndexPath:indexPath];
    row.action();
}

- (IBAction)gotoProfile:(id)sender
{
    [self.navigationController pushViewController:[ADTestAppProfileViewController sharedProfileViewController] animated:YES];
}

@end
