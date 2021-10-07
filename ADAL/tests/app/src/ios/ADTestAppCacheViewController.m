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

#import "ADTestAppCacheViewController.h"
#import "ADTestAppSettings.h"

#import "ADALTokenCacheItem.h"
#import "ADALUserIdentifier.h"
#import "ADALUserInformation.h"

// NOTE: Internal headers should not be consumed in production code
#import "ADALKeychainTokenCache+Internal.h"


@interface ADTestAppCacheRowItem : NSObject

@property BOOL clientId;
@property ADALTokenCacheItem* item;
@property NSString* title;

@end

@implementation ADTestAppCacheRowItem

@end

@interface ADTestAppCacheViewController () <UITableViewDataSource, UITableViewDelegate>

@end

@implementation ADTestAppCacheViewController
{
    UITableView* _cacheTableView;
    
    NSMutableDictionary* _cacheMap;
    
    NSMutableArray* _users;
    NSMutableArray* _userTokens;
    
    NSArray* _tokenRowActions;
    NSArray* _mrrtRowActions;
    NSArray* _clientIdRowActions;
}

- (id)init
{
    if (!(self = [super initWithStyle:UITableViewStylePlain]))
    {
        return nil;
    }
    
    UITabBarItem* tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Cache" image:nil tag:0];
    [self setTabBarItem:tabBarItem];
    
    [self setEdgesForExtendedLayout:UIRectEdgeNone];
    [self setExtendedLayoutIncludesOpaqueBars:NO];
    [[UIScrollView appearance] setContentInsetAdjustmentBehavior:UIScrollViewContentInsetAdjustmentAutomatic];
    return self;
}

- (void)deleteTokenAtPath:(NSIndexPath*)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    
    ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
    [cache removeItem:rowItem.item error:nil];
    
    [self loadCache];
}


- (void)expireTokenAtPath:(NSIndexPath*)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    
    ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
    rowItem.item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:-1.0];
    
    [cache addOrUpdateItem:rowItem.item correlationId:nil error:nil];
    
    [self loadCache];
}

- (void)deleteAllForUserIdClientIdAtPath:(NSIndexPath*)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    if (!rowItem.clientId)
    {
        NSLog(@"Trying to delete all from a non-client-id item?");
        return;
    }
    
    NSString* userId = [_users objectAtIndex:indexPath.section];
    
    ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
    [cache removeAllForUserId:userId clientId:rowItem.title error:nil];
    
    [self loadCache];
}

- (void)deleteAllForClientIdAtPath:(NSIndexPath*)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    if (!rowItem.clientId)
    {
        NSLog(@"Trying to delete all from a non-client-id item?");
        return;
    }
    
    ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
    [cache removeAllForClientId:rowItem.title error:nil];
    
    [self loadCache];
}

- (void)invalidateTokenAtPath:(NSIndexPath*)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    rowItem.item.refreshToken = @"bad-refresh-token";
    
    ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
    [cache addOrUpdateItem:rowItem.item correlationId:nil error:nil];
    
    [self loadCache];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    [self loadCache];
    
    _cacheTableView = self.tableView;
    [_cacheTableView setAutoresizingMask:UIViewAutoresizingFlexibleHeight | UIViewAutoresizingFlexibleWidth];
    [_cacheTableView setDelegate:self];
    [_cacheTableView setDataSource:self];
    [_cacheTableView setAllowsSelection:NO];
    
    // Move the content down so it's not covered by the status bar
    [_cacheTableView setContentInset:UIEdgeInsetsMake(20, 0, 0, 0)];
    [_cacheTableView setContentOffset:CGPointMake(0, -20)];
    
    UIRefreshControl* refreshControl = [[UIRefreshControl alloc] init];
    [refreshControl addTarget:self action:@selector(loadCache) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = refreshControl;
    
    UITableViewRowAction* deleteTokenAction =
    [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleDestructive
                                       title:@"Delete"
                                     handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath)
    {
        [self deleteTokenAtPath:indexPath];
    }];
    
    UITableViewRowAction* invalidateAction =
    [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleNormal
                                       title:@"Invalidate"
                                     handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath)
     {
         [self invalidateTokenAtPath:indexPath];
     }];
    [invalidateAction setBackgroundColor:[UIColor yellowColor]];
    
    UITableViewRowAction* expireTokenAction =
    [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleNormal
                                       title:@"Expire"
                                     handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath)
    {
        [self expireTokenAtPath:indexPath];
    }];
    [expireTokenAction setBackgroundColor:[UIColor orangeColor]];
    
    
    UITableViewRowAction* deleteAllForUserIdClientIdAction =
    [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleDestructive
                                       title:@"Delete this user for this Client"
                                     handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath)
    {
        [self deleteAllForUserIdClientIdAtPath:indexPath];
    }];
    [deleteAllForUserIdClientIdAction setBackgroundColor:[UIColor orangeColor]];
    
    UITableViewRowAction* deleteAllForClientIdAction =
    [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleDestructive
                                       title:@"Delete all users for this Client!"
                                     handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath)
     {
         [self deleteAllForClientIdAtPath:indexPath];
     }];
    
    _tokenRowActions = @[ deleteTokenAction, expireTokenAction ];
    _mrrtRowActions = @[ deleteTokenAction, invalidateAction ];
    _clientIdRowActions = @[ deleteAllForClientIdAction, deleteAllForUserIdClientIdAction ];
    
    [[NSNotificationCenter defaultCenter] addObserverForName:ADTestAppCacheChangeNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification * _Nonnull note)
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self loadCache];
        });
    }];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)addTokenToCacheMap:(ADALTokenCacheItem*)item
{
    NSString* userId = item.userInformation.userId;
    if (!userId)
    {
        userId = @"<unknown>";
    }
    
    NSMutableDictionary* userTokens = [_cacheMap objectForKey:userId];
    if (!userTokens)
    {
        userTokens = [NSMutableDictionary new];
        [_cacheMap setObject:userTokens forKey:userId];
    }
    
    NSString* clientId = item.clientId;
    NSMutableArray* clientIdTokens = [userTokens objectForKey:clientId];
    if (!clientIdTokens)
    {
        clientIdTokens = [NSMutableArray new];
        [userTokens setObject:clientIdTokens forKey:clientId];
    }
    
    [clientIdTokens addObject:item];
}

- (void)loadCache
{
    [self.refreshControl beginRefreshing];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // First create a map heirarchy of userId -> clientId -> tokens to sort
        // through all the itmes we get back
        ADALKeychainTokenCache* cache = [ADALKeychainTokenCache new];
        NSArray* allItems = [cache allItems:nil];
        _cacheMap = [NSMutableDictionary new];
        for (ADALTokenCacheItem* item in allItems)
        {
            [self addTokenToCacheMap:item];
        }
        
        // Now that we have all the items sorted out in the dictionaries flatten it
        // out to a single list.
        _users = [[NSMutableArray alloc] initWithCapacity:_cacheMap.count];
        _userTokens = [[NSMutableArray alloc] initWithCapacity:_cacheMap.count];
        for (NSString* userId in _cacheMap)
        {
            NSUInteger count = 0;
            [_users addObject:userId];
            
            NSDictionary* userTokens = [_cacheMap objectForKey:userId];
            for (NSString* key in userTokens)
            {
                count += [[userTokens objectForKey:key] count]  + 1; // Add one for the "client ID" item
            }
            
            NSMutableArray* arrUserTokens = [[NSMutableArray alloc] initWithCapacity:count];
            
            for (NSString* clientId in userTokens)
            {
                ADTestAppCacheRowItem* clientIdItem = [ADTestAppCacheRowItem new];
                clientIdItem.title = clientId;
                clientIdItem.clientId = YES;
                
                [arrUserTokens addObject:clientIdItem];
                
                NSArray* clientIdTokens = [userTokens objectForKey:clientId];
                for (ADALTokenCacheItem* item in clientIdTokens)
                {
                    ADTestAppCacheRowItem* tokenItem = [ADTestAppCacheRowItem new];
                    NSString* resource = item.resource;
                    if (!resource)
                    {
                        if ([clientId hasPrefix:@"foci-"])
                        {
                            resource = @"<FRT>";
                        }
                        else if (item.familyId)
                        {
                            resource = [NSString stringWithFormat:@"<MRRT (F=%@)>", item.familyId];
                        }
                        else
                        {
                            resource = @"<MRRT>";
                        }
                    }
                    tokenItem.title = resource;
                    tokenItem.item = item;
                    
                    [arrUserTokens addObject:tokenItem];
                }
            }
            
            [_userTokens addObject:arrUserTokens];
        }
        
        _cacheMap = nil;
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [_cacheTableView reloadData];
            [self.refreshControl endRefreshing];
        });
    });
    
    
    
}

- (ADTestAppCacheRowItem*)cacheItemForPath:(NSIndexPath*)indexPath
{
    return [[_userTokens objectAtIndex:indexPath.section] objectAtIndex:indexPath.row];
}

- (BOOL)isPathClientId:(NSIndexPath*)indexPath
{
    return [self cacheItemForPath:indexPath].clientId;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return [_users count];
}

- (nullable NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    return [_users objectAtIndex:section];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return [[_userTokens objectAtIndex:section] count];
}

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"cacheCell"];
    
    if (!cell)
    {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"cacheCell"];
    }
    
    ADTestAppCacheRowItem* cacheItem = [self cacheItemForPath:indexPath];
    
    if (cacheItem.clientId)
    {
        [cell setBackgroundColor:[UIColor colorWithRed:0 green:0 blue:((CGFloat)0x80/(CGFloat)0xFF) alpha:1.0]];
        [[cell textLabel] setTextColor:[UIColor whiteColor]];
        [[cell textLabel] setFont:[UIFont preferredFontForTextStyle:UIFontTextStyleBody]];
    }
    else
    {
        [cell setBackgroundColor:[UIColor whiteColor]];

        if ([cacheItem.item.refreshToken isEqualToString:@"bad-refresh-token"])
        {
            [[cell textLabel] setTextColor:[UIColor yellowColor]];
        }
        else if (cacheItem.item.isExpired)
        {
            [[cell textLabel] setTextColor:[UIColor orangeColor]];
        }
        else
        {
            [[cell textLabel] setTextColor:[UIColor blackColor]];
        }
        [[cell textLabel] setFont:[UIFont preferredFontForTextStyle:UIFontTextStyleBody]];
    }
    
    [[cell textLabel] setText:cacheItem.title];
    
    return cell;
}

- (nullable NSArray<UITableViewRowAction *> *)tableView:(UITableView *)tableView
                           editActionsForRowAtIndexPath:(NSIndexPath *)indexPath
{
    ADTestAppCacheRowItem* rowItem = [self cacheItemForPath:indexPath];
    if (rowItem.clientId)
    {
        return _clientIdRowActions;
    }
    else
    {
        if (rowItem.item.resource)
        {
            return _tokenRowActions;
        }
        else
        {
            return _mrrtRowActions;
        }
    }
}

- (void)tableView:(UITableView*)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath*)indexPath
{
    // All tasks are handled by blocks defined in editActionsForRowAtIndexPath, however iOS8 requires this method to enable editing
}


@end
