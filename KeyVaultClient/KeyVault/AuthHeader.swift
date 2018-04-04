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

import Foundation

extension String {
    static let notWhitespace = CharacterSet.whitespacesAndNewlines.inverted
    func isNotBlankOrEmpty() -> Bool {
        if self.count == 0 {
            return false
        }
        
        guard let range = self.rangeOfCharacter(from: String.notWhitespace) else {
            return false
        }
        
        return !range.isEmpty
    }
}

extension Substring {
    static let notWhitespace = CharacterSet.whitespacesAndNewlines.inverted
    func isNotBlankOrEmpty() -> Bool {
        if self.count == 0 {
            return false
        }
        
        guard let range = self.rangeOfCharacter(from: Substring.notWhitespace) else {
            return false
        }
        
        return !range.isEmpty
    }
}

internal class AuthHeader {
    enum AuthHeaderError : Error {
        case EmptyString
        case InvalidHeader
    }
    
    internal class func extractItems(_ authHeader: String) -> [Substring] {
        var result = [] as [Substring]
        var stIdx = authHeader.startIndex
        var curIdx = authHeader.startIndex
        var skipNext = false
        var quoted = false
        var advanceSt = false
        var collect = false
        var collect2 = false
        
        for c in authHeader {
            if skipNext {
                skipNext = false
            } else if c == "\\" {
                skipNext = true
            } else if quoted {
                if c == "\"" {
                    quoted = false
                    result.append(authHeader[stIdx..<curIdx])
                    advanceSt = true
                }
            } else if c == "\"" {
                quoted = true
                advanceSt = true
            } else if c == " " {
                collect = true
            } else if c == "=" {
                collect2 = true
            } else if c == "," {
                collect2 = true
            }
            
            if collect || collect2 {
                let sub = authHeader[stIdx..<curIdx]
                if sub.isNotBlankOrEmpty() {
                    result.append(sub)
                }
                advanceSt = true
                collect = false
            }
            
            if collect2 {
                result.append(authHeader[curIdx...curIdx])
                collect2 = false
            }
            
            curIdx = authHeader.index(after: curIdx)
            if (advanceSt) {
                stIdx = curIdx
                advanceSt = false
            }
        }
        
        let sub = authHeader[stIdx..<curIdx]
        if sub.isNotBlankOrEmpty() {
            result.append(sub)
        }
        
        return result
    }
    
    enum ParserState {
        case LookingForChallenge
        case LookingForParam
        case LookingForEquals(Substring)
        case LookingForValue(Substring)
        case LookingForComma
        case LookingForChallengeOrParam
        case LookingForEqualsOrParam(Substring)
    }
    
    internal class func parse(_ authHeader: String) throws -> [Substring : [Substring : Substring]] {
        if !authHeader.isNotBlankOrEmpty() {
            throw AuthHeaderError.EmptyString
        }
        
        let items = extractItems(authHeader)
        if (items.count == 0) {
            return [:]
        }
        
        var result = [:] as [Substring : [Substring : Substring]]
        var curChallenge = nil as Substring?
        var curParams = [:] as [Substring : Substring]
        
        var state = ParserState.LookingForChallenge
        
        for item in items {
            switch state {
            case .LookingForChallenge :
                if item == "=" || item == "," { throw AuthHeaderError.InvalidHeader }
                curChallenge = item
                state = .LookingForParam
            case .LookingForParam :
                if item == "=" || item == "," { throw AuthHeaderError.InvalidHeader }
                state = .LookingForEquals(item)
            case .LookingForEquals(let key) :
                if item != "=" { throw AuthHeaderError.InvalidHeader }
                state = .LookingForValue(key)
            case .LookingForValue(let key) :
                if item == "=" || item == "," { throw AuthHeaderError.InvalidHeader }
                curParams[key] = item
                state = .LookingForComma
            case .LookingForComma :
                if item != "," { throw AuthHeaderError.InvalidHeader }
                state = .LookingForChallengeOrParam
            case .LookingForChallengeOrParam :
                if item == "=" || item == "," { throw AuthHeaderError.InvalidHeader }
                state = .LookingForEqualsOrParam(item)
            case .LookingForEqualsOrParam(let challengeOrParam) :
                if item == "," { throw AuthHeaderError.InvalidHeader }
                if item == "=" {
                    state = .LookingForValue(challengeOrParam)
                } else {
                    result[curChallenge!] = curParams
                    curParams = [:]
                    curChallenge = challengeOrParam
                    state = .LookingForParam
                }
            }
        }
        
        guard let challenge = curChallenge else {
            return [:]
        }
        
        result[challenge] = curParams
        return result
    }
}
