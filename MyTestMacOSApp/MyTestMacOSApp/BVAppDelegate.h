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

#import <Cocoa/Cocoa.h>

@interface BVAppDelegate : NSObject <NSApplicationDelegate>
{
//@private:
    IBOutlet NSWindow *_window;
    IBOutlet NSTextView *_resultField;
    IBOutlet NSTextView *_samlAssertionField;
    NSPersistentStoreCoordinator *_persistentStoreCoordinator;
    NSManagedObjectModel         *_managedObjectModel;
    NSManagedObjectContext       *_managedObjectContext;
}

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSTextView *resultField;
@property (assign) IBOutlet NSTextView *samlAssertionField;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;
- (IBAction)endToEndAction:(id)sender;
- (IBAction)showUsersAction:(id)sender;
- (IBAction)expireAllAction:(id)sender;
- (IBAction)clearCacheAndCookiesAction:(id)sender;
- (IBAction)refreshTokenFlowAction:(id)sender;
- (IBAction)acquireTokenSilentAction:(id)sender;
- (IBAction)promptAlwaysAction:(id)sender;
- (IBAction)samlAssertionAction:(id)sender;

@end
