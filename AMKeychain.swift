/*
The MIT License (MIT)

Copyright (c) 2014 _tid_

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
import Foundation
import Security

public class AMKeychain {
    public typealias failureClosure = ((NSError) -> Void)
    
    public class func setPassword(serviceName: String, account: String, password: String,
        failure: failureClosure? = nil) -> Bool {
        var query = Query()
        query.service  = serviceName
        query.account  = account
        query.password = password
        return query.addOrUpdate(failure: failure)
    }
    
    public class func getPassword(serviceName: String, account: String,
        failure: failureClosure? = nil) -> String? {
        var query = Query()
        query.service = serviceName
        query.account = account
        return query.select(failure: failure)?.password
    }
    
    public class func deletePassword(serviceName: String, account: String,
        failure: failureClosure? = nil) -> Bool {
        var query = Query()
        query.service = serviceName
        query.account = account
        return query.delete(failure: failure)
    }
    
    public class func getAccounts(serviceName: String, failure: failureClosure? = nil) -> [String]? {
        var accounts : [String]? = []
        var query = Query()
        query.service = serviceName
        
        if let results = query.selectAll(failure: failure) {
            for result in results {
                if let account = result.account {
                    accounts?.append(account)
                }
            }
            return accounts
        } else {
            return nil
        }
    }
    
    public class func getAccounts(failure: failureClosure? = nil) -> [String]? {
        var accounts : [String]? = []
        var query = Query()
        if let results = query.selectAll(failure: failure) {
            for result in results {
                if let account = result.account {
                    accounts?.append(account)
                }
            }
            return accounts
        } else {
            return nil
        }
    }
}

extension AMKeychain {
    private class Attribute {
        private var secClass          : SecClass? = .GenericPassword
        private var secAttrAccessible : SecAttrAccessible? = .WhenUnlocked
        private var accessGroup       : String? = nil
        private var createDate        : String? = nil
        private var modificationDate  : String? = nil
        private var description       : String? = nil
        private var comment           : String? = nil
        private var creator           : String? = nil
        private var type              : String? = nil
        private var label             : String? = nil
        private var IsInvisible       : String? = nil
        private var IsNegative        : String? = nil
        private var service           : String? = nil
        private var account           : String? = nil
        private var passwordData      : NSData? = nil
        
        private var password: String? {
            set {
                self.passwordData = newValue?.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
            }
            
            get {
                if let data = self.passwordData {
                    return NSString(data: data, encoding: NSUTF8StringEncoding)
                }
                return nil
            }
        }
    }
    
    private typealias QueryResult = Attribute
    
    private class Query : Attribute {
        private override init() {
        }
        
        private func add(failure: failureClosure? = nil) -> Bool {
            var query = make()
            query.setValue(passwordData, forKey: kSecValueData as String)
            
            let status = SecItemAdd(query as CFDictionaryRef, nil)
            if let error = getError(status) {
                failure?(error)
            }
            
            return status == errSecSuccess
        }
        
        private func addOrUpdate(failure: failureClosure? = nil)  -> Bool {
            delete()
            return add(failure: failure)
        }
        
        private func delete(failure: failureClosure? = nil) -> Bool {
            var query = make()
            
            let status = SecItemDelete(query as CFDictionaryRef)
            if let error = getError(status) {
                failure?(error)
            }
            return status == errSecSuccess
        }
        
        private func select(failure: failureClosure? = nil) -> QueryResult? {
            var result : QueryResult? = nil
            var query = make()
            query.setValue(kCFBooleanTrue, forKey: kSecReturnData as String)
            query.setValue(kSecMatchLimitOne as String, forKey: kSecMatchLimit as String)
            
            var dataTypeRef : Unmanaged<AnyObject>?
            let status = SecItemCopyMatching(query, &dataTypeRef)
            if status == errSecSuccess {
                result = QueryResult()
                result?.passwordData = dataTypeRef?.takeRetainedValue() as? NSData
            }

            if let error = getError(status) {
                failure?(error)
            }
            
            return result
        }
        
        private func selectAll(failure: failureClosure? = nil) -> [QueryResult]? {
            var results : [QueryResult]? = []
            var query = make()
            query.setValue(kCFBooleanTrue, forKey: kSecReturnData as String)
            query.setValue(kCFBooleanTrue, forKey: kSecReturnAttributes as String)
            query.setValue(kSecMatchLimitAll as String, forKey: kSecMatchLimit as String)
            
            var dataTypeRef : Unmanaged<AnyObject>?
            let status = SecItemCopyMatching(query, &dataTypeRef)
            if status == errSecSuccess {
                if let value : AnyObject? = dataTypeRef?.takeRetainedValue() {
                    switch value {
                    case let data as NSData:
                        var result = QueryResult()
                        result.passwordData = data
                        results?.append(result)
                    case let datas as NSArray:
                        println(datas)
                        for data in datas {
                            println(data)
                            println(data["acct"])
                            var result = QueryResult()
                            result.account      = data["acct"] as? String
                            result.accessGroup  = data["agrp"] as? String
                            result.service      = data["svce"] as? String
                            result.passwordData = data["v_Data"] as? NSData
                            results?.append(result)
                        }
                    default:
                        results = nil                    }
                }
            }
            
            if let error = getError(status) {
                results = nil
                failure?(error)
            }
            
            return results
        }
        
        
        private func make() -> NSMutableDictionary {
            var query = NSMutableDictionary()
            query.setValue(self.secClass?.rawValue, forKey: kSecClass as String)
            query.setValue(self.service,            forKey: kSecAttrService as String)
            query.setValue(self.account,            forKey: kSecAttrAccount as String)
            return query
        }
        
        private func getError(status: OSStatus) -> NSError? {
            var msg = ""
            switch (status) {
                case errSecAllocate:
                    msg = "errSecAllocate"
                case errSecAuthFailed:
                    msg = "errSecAuthFailed"
                case errSecDecode:
                    msg = "errSecDecode"
                case errSecDuplicateItem:
                    msg = "errSecDuplicateItem"
                case errSecInteractionNotAllowed:
                    msg = "errSecInteractionNotAllowd"
                case errSecItemNotFound:
                    msg = "errSecItemNotFound"
                case errSecNotAvailable:
                    msg = "errSecNotAvailable"
                case errSecParam:
                    msg = "errSecParam"
                case errSecUnimplemented:
                    msg = "errSecUnimplemented"
                case errSecSuccess:
                    return nil
                default:
                    return nil
            }
            
            return NSError(domain: "", code: Int(status), userInfo: ["msg":msg])
        }
    }
}

extension AMKeychain {
    private enum SecAttrAccessible : RawRepresentable {
        case AfterFirstUnlock
        case AfterFirstUnlockThisDeviceOnly
        case Always
        case AlwaysThisDeviceOnly
        case WhenUnlocked
        case WhenUnlockedThisDeviceOnly
        
        private init?(rawValue: String) {
            switch rawValue {
            case kSecAttrAccessibleAfterFirstUnlock:
                self = AfterFirstUnlock
            case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
                self = AfterFirstUnlockThisDeviceOnly
            case kSecAttrAccessibleAlways:
                self = Always
            case kSecAttrAccessibleAlwaysThisDeviceOnly:
                self = AlwaysThisDeviceOnly
            case kSecAttrAccessibleWhenUnlocked:
                self = WhenUnlocked
            case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
                self = WhenUnlockedThisDeviceOnly
            default:
                return nil
            }
        }
        
        private var rawValue: String {
            switch self {
            case .AfterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .AfterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .Always:
                return kSecAttrAccessibleAlways
            case .AlwaysThisDeviceOnly:
                return kSecAttrAccessibleAlwaysThisDeviceOnly
            case .WhenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .WhenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            default:
                return kSecAttrAccessibleWhenUnlocked
            }
        }
    }
    
    private enum SecClass : RawRepresentable {
        case GenericPassword
        case InternetPassword
        case Certificate
        case Key
        case Identity
        
        private init?(rawValue: String) {
            switch rawValue {
            case kSecClassGenericPassword:
                self = GenericPassword
            case kSecClassInternetPassword:
                self = InternetPassword
            case kSecClassCertificate:
                self = Certificate
            case kSecClassKey:
                self = Key
            case kSecClassIdentity:
                self = Identity
            default:
                return nil
            }
        }
        
        private var rawValue: String {
            switch self {
            case .GenericPassword:
                return kSecClassGenericPassword
            case .InternetPassword:
                return kSecClassInternetPassword
            case .Certificate:
                return kSecClassCertificate
            case .Key:
                return kSecClassKey
            case .Identity:
                return kSecClassIdentity
            default:
                return kSecClassGenericPassword
            }
        }
    }
}
