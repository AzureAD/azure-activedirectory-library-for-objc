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

#import "ADTestAppCacheWindowController.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"
#import "ADTestAppCache.h"
#import "ADLogger+Internal.h"

@interface NSString (ADTestApp)

- (NSString *)truncatedHash;

@end

@implementation NSString (ADTestApp)

- (NSString *)truncatedHash
{
    return [ADLogger getHash:self];
}

@end

@interface ADTestAppCacheWindowController () <NSTableViewDelegate, NSTableViewDataSource>

@end

@implementation ADTestAppCacheWindowController

+ (ADTestAppCacheWindowController*)controller
{
    static dispatch_once_t once;
    static ADTestAppCacheWindowController* controller = nil;
    
    dispatch_once(&once, ^{
        controller = [self new];
    });
    
    return controller;
}

+ (void)showWindow
{
    [[self controller] showWindow:nil];
}

- (id)init
{
    if (!(self = [super initWithWindowNibName:@"CacheWindow"]))
    {
        return nil;
    }
    
    [self reloadCache];
    
    return self;
}

- (void)windowDidLoad {
    [super windowDidLoad];
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
}

- (void)reloadCache
{
    _allItems = [[ADTokenCache defaultCache] allItems:nil];
    [_tableView reloadData];
}

- (IBAction)reload:(id)sender
{
    [self reloadCache];
    
}

#pragma mark -
#pragma mark NSTableViewDataSource implementation

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
    return [_allItems count];
}

- (NSString *)dataForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row
{
    ADTokenCacheItem* item = [_allItems objectAtIndex:row];
    
    NSString* identifier = tableColumn.identifier;
    if ([identifier isEqualToString:@"upn"])
    {
        return item.userInformation.userId;
    }
    else if ([identifier isEqualToString:@"authority"])
    {
        return item.authority;
    }
    else if ([identifier isEqualToString:@"clientId"])
    {
        return item.clientId;
    }
    else if ([identifier isEqualToString:@"resource"])
    {
        return item.resource;
    }
    else if ([identifier isEqualToString:@"accessToken"])
    {
        return item.accessToken.truncatedHash;
    }
    else if ([identifier isEqualToString:@"expiresOn"])
    {
        return [item.expiresOn description];
    }
    else if ([identifier isEqualToString:@"refreshToken"])
    {
        NSString* refreshToken = item.refreshToken;
        if ([refreshToken isEqualToString:@"<bad-refresh-token>"])
        {
            return @"<bad-rt>";
        }
        return item.refreshToken.truncatedHash;
    }
    else
    {
        @throw @"Unrecongized identifier";
    }
}

static NSLineBreakMode linebreakForColumn(NSTableColumn* tableColumn)
{
    if (!tableColumn)
    {
        return NSLineBreakByTruncatingMiddle;
    }
    
    NSString* identifier = tableColumn.identifier;
    
    if ([identifier isEqualToString:@"upn"] || [identifier isEqualToString:@"expiresOn"])
    {
        return NSLineBreakByTruncatingTail;
    }
    
    return NSLineBreakByTruncatingMiddle;
}

/* View Based TableView:
 Non-bindings: This method is required if you wish to turn on the use of NSViews instead of NSCells. The implementation of this method will usually call -[tableView makeViewWithIdentifier:[tableColumn identifier] owner:self] in order to reuse a previous view, or automatically unarchive an associated prototype view for that identifier. The -frame of the returned view is not important, and it will be automatically set by the table. 'tableColumn' will be nil if the row is a group row. Returning nil is acceptable, and a view will not be shown at that location. The view's properties should be properly set up before returning the result.
 */
- (nullable NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row
{
    
    NSTextField* cell = [tableView makeViewWithIdentifier:@"CacheTextCell" owner:self];
    
    if (!cell)
    {
        cell = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, tableView.frame.size.width, 20)];
        cell.bordered = NO;
        cell.drawsBackground = NO;
        cell.identifier = @"CacheTextCell";
        cell.lineBreakMode = linebreakForColumn(tableColumn);
    }
    
    NSString* text = [self dataForTableColumn:tableColumn row:row];
    cell.stringValue = text ? text : @"";
    return cell;
}

- (IBAction)expire:(id)sender
{
    @synchronized (self)
    {
        NSIndexSet* rows = [_tableView selectedRowIndexes];
        
        [rows enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL * _Nonnull stop)
         {
             ADTokenCacheItem* item = _allItems[idx];
             if (item.expiresOn)
             {
                 item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:-1.0];
             }
             
             [[ADTokenCache defaultCache] addOrUpdateItem:item correlationId:nil error:nil];
         }];
        
        [self reloadCache];
    }
}

- (IBAction)delete:(id)sender
{
    @synchronized (self)
    {
        NSIndexSet* rows = [_tableView selectedRowIndexes];
        
        [rows enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL * _Nonnull stop)
         {
             ADTokenCacheItem* item = _allItems[idx];
             [[ADTokenCache defaultCache] removeItem:item error:nil];
         }];
        
        [self reloadCache];
    }
}

- (IBAction)invalidate:(id)sender
{
    @synchronized (self)
    {
        NSIndexSet* rows = [_tableView selectedRowIndexes];
        
        [rows enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL * _Nonnull stop)
         {
             ADTokenCacheItem* item = _allItems[idx];
             if (item.refreshToken)
             {
                 item.refreshToken = @"<bad-refresh-token>";
             }
             
             [[ADTokenCache defaultCache] addOrUpdateItem:item correlationId:nil error:nil];
         }];
        
        [self reloadCache];
    }
}

@end
