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

#import "ADAutoParameterViewController.h"

@interface ADAutoParameterViewController ()

@end

@implementation ADAutoParameterViewController
{
    NSArray<NSString*> * _parameters;
    ADAutoParamBlock _completion;
    NSArray<UITextField*> * _textFields;
    UIStackView* _stackView;
}

- (void)loadView
{
    UIView* rootView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    rootView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    rootView.translatesAutoresizingMaskIntoConstraints = YES;
    rootView.autoresizesSubviews = NO;
    rootView.backgroundColor = UIColor.whiteColor;
    self.view = rootView;
    
    UIStackView* stackView = [[UIStackView alloc] init];
    //stackView.autoresizingMask = UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
    stackView.axis = UILayoutConstraintAxisVertical;
    stackView.spacing = 4.0;
    stackView.alignment = UIStackViewAlignmentFill;
    stackView.translatesAutoresizingMaskIntoConstraints = NO;
    stackView.backgroundColor = UIColor.whiteColor;
    
    NSMutableArray* fields = [[NSMutableArray alloc] initWithCapacity:_parameters.count];
    
    for (NSString* param in _parameters)
    {
        UITextField* tf = [[UITextField alloc] init];
        tf.accessibilityIdentifier = param;
        tf.placeholder = param;
        tf.borderStyle = UITextBorderStyleLine;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        [stackView addArrangedSubview:tf];
        [fields addObject:tf];
    }
    
    _textFields = fields;
    
    UIButton* goButton = [[UIButton alloc] init];
    [goButton setTitle:@"Go" forState:UIControlStateNormal];
    [goButton addTarget:self
                 action:@selector(go:)
       forControlEvents:UIControlEventTouchUpInside];
    goButton.backgroundColor = UIColor.greenColor;
    goButton.titleLabel.textColor = UIColor.whiteColor;
    goButton.accessibilityIdentifier = @"GoButton";
    [stackView addArrangedSubview:goButton];
    
    [rootView addSubview:stackView];
    
    
    UILayoutGuide* margins = self.view.layoutMarginsGuide;
    [stackView.topAnchor constraintEqualToAnchor:self.topLayoutGuide.bottomAnchor].active = YES;
    [stackView.leadingAnchor constraintEqualToAnchor:margins.leadingAnchor].active = YES;
    [stackView.trailingAnchor constraintEqualToAnchor:margins.trailingAnchor constant:8.0].active = YES;
    [stackView setNeedsLayout];
    
    /*[rootView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:8.0].active = YES;
    [rootView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor constant:8.0].active = YES;*/
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (id)initWithParameters:(NSArray<NSString*>*)parameters
         completionBlock:(ADAutoParamBlock)completionBlock
{
    if (!(self = [super init]))
    {
        return nil;
    
    }
    
    _parameters = parameters;
    _completion = completionBlock;
    
    return self;
}

- (IBAction)go:(id)sender
{
    (void)sender;
    
    @synchronized (self)
    {
        NSMutableDictionary* params = [NSMutableDictionary new];
        for (UITextField* field in _textFields)
        {
            params[field.accessibilityIdentifier] = field.text;
        }
        
        _completion(params);
        _completion = nil;
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
