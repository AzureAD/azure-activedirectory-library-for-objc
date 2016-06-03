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


#import "ADTestAppCacheViewController.h"

#import <ADALiOS/ADAL.h>
#import "ADTestAppSettings.h"
#import "ADTestAppLogger.h"

@interface ADTestAppCacheViewController ()

@end

@implementation ADTestAppCacheViewController

NSMutableArray *tableData;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.cacheTable.rowHeight = UITableViewAutomaticDimension;
    self.cacheTable.estimatedRowHeight = 122.0;
    
    [self.cacheTable setDelegate:self];
    [self.cacheTable setDataSource:self];
}

- (void)viewWillAppear:(BOOL)animated {
    tableData = [NSMutableArray new];
    [self loadTableFromCache];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (void)loadTableFromCache {
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItems:&error];
    if (!error)
    {
        for(ADTokenCacheStoreItem* item in array)
        {
            [tableData addObject:item.description];
        }
        
        [_cacheTable reloadData];
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

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return [tableData count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *simpleTableIdentifier = @"SimpleTableItem";
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:simpleTableIdentifier];
    
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:simpleTableIdentifier];
    }
    
    cell.textLabel.text = [tableData objectAtIndex:indexPath.row];
    return cell;
}


- (IBAction)deleteAllPressed:(id)sender
{
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    [cache removeAll:&error];
}


- (IBAction)expireAllPressed:(id)sender
{
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItems:&error];
    if (error)
    {
        [ADTestAppLogger logMessage:[NSString stringWithFormat:@"Expire All failed to retrieve allItems: %@", error.errorDetails]
                               type:TALogError];
        return;
    }
    for(ADTokenCacheStoreItem* item in array)
    {
        item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
        [cache addOrUpdateItem:item error:&error];
    }
    
    if (error)
    {
        [ADTestAppLogger logMessage:[NSString stringWithFormat:@"Expire All failed to update item: %@", error.errorDetails]
                               type:TALogError];
    }
    else
    {
        [ADTestAppLogger logMessage:@"Successfully expired all tokens." type:TALogSuccess];
    }
}

@end
