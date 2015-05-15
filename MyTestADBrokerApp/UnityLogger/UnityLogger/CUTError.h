/*
 Copyright © 2013 Microsoft. All rights reserved.
 
 Synopsis: Definition of the common error code
 
 Owner: yiweizha
 Created: 9/26/2013
 */


/**
 @details common utility library error codes.
 */

#import <Foundation/Foundation.h>
typedef NS_ENUM(NSInteger, CUTErrorCode)
{
    CUTErrorUndefined = 0,
    CUTErrorNotImplemented = 1,
    CUTErrorTypeMismatch = 2,
    CUTErrorObjectIsNil = 3,
    CUTErrorOperationNotSupported = 4,
    CUTErrorInvalidFormat = 5,
    CUTErrorInvalidArgument = 6,
};
