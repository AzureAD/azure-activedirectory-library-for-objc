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

#import <Cocoa/Cocoa.h>

@class ADTestMemoryCache;
@class ADTokenCache;

@interface ADTestAppDelegate : NSObject <NSApplicationDelegate>
{
//@private:
    IBOutlet NSWindow *_window;
    IBOutlet NSTextView *_resultField;
    IBOutlet NSTextView *_samlAssertionField;
    NSPersistentStoreCoordinator *_persistentStoreCoordinator;
    NSManagedObjectModel         *_managedObjectModel;
    NSManagedObjectContext       *_managedObjectContext;
    ADTestMemoryCache* _cacheDelegate;
    ADTokenCache* _cache;
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
- (IBAction)acquireTokenSilentAction:(id)sender;
- (IBAction)promptAlwaysAction:(id)sender;
- (IBAction)samlAssertionAction:(id)sender;

@end
