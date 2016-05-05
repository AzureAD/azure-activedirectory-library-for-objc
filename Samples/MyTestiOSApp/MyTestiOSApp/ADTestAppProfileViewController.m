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

#import "ADTestAppProfileViewController.h"
#import "ADTestAppSettings.h"

static NSDictionary* s_profiles = nil;
static NSArray* s_profileTitles = nil;

@interface ADTestAppProfileViewController ()

@end

@implementation ADTestAppProfileViewController
{
    UITableView* _profileTable;
}

+ (void)initialize
{
    s_profiles =
    @{ @"Test App"    : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://graph.windows.net",
                           // NOTE: The settings below should come from your registered application on
                           //       the azure management portal.
                           @"clientId" : @"b92e0ba5-f86e-4411-8e18-6b5f928d968a",
                           @"redirectUri" : @"x-msauth-adaltestapp-210://com.microsoft.adal.2.1.0.TestApp",
                           },
       @"Office"      : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://api.office.com/discovery",
                           @"clientId" : @"d3590ed6-52b3-4102-aeff-aad2292ab01c",
                           @"redirectUri" : @"urn:ietf:wg:oauth:2.0:oob",
                           },
       @"OneDrive"    : @{ @"authority" : @"https://login.microsoftonline.com/common",
                           @"resource" : @"https://api.office.com/discovery",
                           @"clientId" : @"af124e86-4e96-495a-b70a-90f90ab96707",
                           @"redirectUri" : @"ms-onedrive://com.microsoft.skydrive",
                           },
       };
    
    s_profileTitles = @[ @"Test App", @"Office", @"OneDrive" ];
    
    NSDictionary* profileDict = [s_profiles objectForKey:[self currentProfileTitle]];
    [[ADTestAppSettings settings] setFromDictionary:profileDict];
}

+ (NSString*)currentProfileTitle
{
    NSString* currentProfile = [[NSUserDefaults standardUserDefaults] stringForKey:@"CurrentProfile"];
    
    return currentProfile ? currentProfile : @"Test App";
}

+ (ADTestAppProfileViewController*)sharedProfileViewController
{
    static ADTestAppProfileViewController* s_profileViewController = nil;
    static dispatch_once_t s_once;
    
    dispatch_once(&s_once, ^{
        s_profileViewController = [[ADTestAppProfileViewController alloc] init];
    });
    
    return s_profileViewController;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    self.navigationController.navigationBarHidden = NO;
    self.navigationItem.hidesBackButton = NO;
    self.navigationItem.title = @"Select Application Profile";
    
    UIView* rootView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    [rootView setAutoresizesSubviews:YES];
    [rootView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    _profileTable = [[UITableView alloc] initWithFrame:rootView.frame];
    [_profileTable setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [_profileTable setDataSource:self];
    
    NSString* currentProfile = [ADTestAppProfileViewController currentProfileTitle];
    NSIndexPath* indexPath = [NSIndexPath indexPathForRow:[s_profileTitles indexOfObject:currentProfile] inSection:0];
    [_profileTable selectRowAtIndexPath:indexPath
                               animated:NO
                         scrollPosition:UITableViewScrollPositionNone];
    [_profileTable setDelegate:self];
    [rootView addSubview:_profileTable];
    
    self.view = rootView;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    NSString* rowTitle = [s_profileTitles objectAtIndex:indexPath.row];
    NSDictionary* rowDict = [s_profiles objectForKey:rowTitle];
    [[ADTestAppSettings settings] setFromDictionary:rowDict];
    [[NSUserDefaults standardUserDefaults] setObject:rowTitle forKey:@"CurrentProfile"];
    [self.navigationController popViewControllerAnimated:YES];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return [s_profileTitles count];
}

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"profileCell"];
    if (!cell)
    {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"profileCell"];
    }

    NSString* title = [s_profileTitles objectAtIndex:indexPath.row];
    [[cell textLabel] setText:title];
    
    return cell;
}

@end
