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

#import "ADAutoInputViewController.h"

@interface ADAutoInputViewController ()

@end

@implementation ADAutoInputViewController
{
    ADAutoParamBlock _completionBlock;
    UITextView * _inputTextview;
}

- (id)initWithCompletionBlock:(ADAutoParamBlock)completionBlock
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _completionBlock = completionBlock;
    
    return self;
}

- (void)loadView
{
    UIView* rootView = [[UIView alloc] initWithFrame:UIScreen.mainScreen.bounds];
    rootView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    rootView.translatesAutoresizingMaskIntoConstraints = YES;
    rootView.autoresizesSubviews = NO;
    rootView.backgroundColor = UIColor.whiteColor;
    self.view = rootView;
    
    UITextView* textView = [[UITextView alloc] init];
    textView.autocorrectionType = UITextAutocorrectionTypeNo;
    textView.accessibilityIdentifier = @"inputTextview";
    textView.translatesAutoresizingMaskIntoConstraints = NO;
    textView.editable = YES;
    textView.layer.cornerRadius = 8.0;
    textView.layer.borderWidth = 1.0;
    textView.layer.borderColor = UIColor.lightGrayColor.CGColor;

    _inputTextview = textView;
    
    UIButton* goButton = [[UIButton alloc] init];
    [goButton setTitle:@"Go" forState:UIControlStateNormal];
    [goButton addTarget:self
                 action:@selector(go:)
       forControlEvents:UIControlEventTouchUpInside];
    goButton.backgroundColor = UIColor.greenColor;
    goButton.titleLabel.textColor = UIColor.whiteColor;
    goButton.translatesAutoresizingMaskIntoConstraints = NO;
    goButton.accessibilityIdentifier = @"GoButton";
    
    [rootView addSubview:textView];
    [rootView addSubview:goButton];
    
    UILayoutGuide* margins = self.view.layoutMarginsGuide;
    [textView.topAnchor constraintEqualToAnchor:self.topLayoutGuide.bottomAnchor constant:8.0].active = YES;
    [textView.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
    [textView.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor].active = YES;
    [textView.bottomAnchor constraintEqualToAnchor:goButton.topAnchor constant:-8.0].active = YES;
    [goButton.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
    [goButton.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor].active = YES;
    [goButton.heightAnchor constraintEqualToConstant:20.0];
    [goButton.bottomAnchor constraintEqualToAnchor:self.bottomLayoutGuide.topAnchor constant:-8.0].active = YES;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)go:(id)sender
{
    (void)sender;
    
    @synchronized (self)
    {
        NSString* text = _inputTextview.text;
        NSError* error = nil;
        NSDictionary* params = [NSJSONSerialization JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&error];
        if (!params)
        {
            params = @{ @"error" : error };
        }
        
        _completionBlock(params);
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

@end
