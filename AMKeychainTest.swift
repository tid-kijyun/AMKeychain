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
import UIKit
import XCTest

class keychainTestTests: XCTestCase {
    let SERVICE_NAME = "MyService"
    let account = "oreore"
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testAMKeychain() {
        var result = false
        var pass : String?  = ""
        let pass1  = "testpass1"
        let pass2  = "testpass2"
        
        // set(add)
        result = AMKeychain.setPassword(SERVICE_NAME, account: account, password: pass1) {
            (error) in
            println(error)
        }
        XCTAssert(result, "Pass")
        
        // get
        pass = AMKeychain.getPassword(SERVICE_NAME, account: account) {
            (error) in
            println(error)
        }
        XCTAssertNotNil(pass, "Pass")
        XCTAssert(pass == pass1, "Pass")
        
        // set(update)
        result = AMKeychain.setPassword(SERVICE_NAME, account: account, password: pass2) {
            (error) in
            println(error)
        }
        XCTAssert(result, "Pass")
        
        // get
        pass = AMKeychain.getPassword(SERVICE_NAME, account: account) {
            (error) in
            println(error)
        }
        XCTAssertNotNil(pass, "Pass")
        XCTAssert(pass == pass2, "Pass")
        
        // account check
        let accounts = AMKeychain.getAccounts(SERVICE_NAME) {
            (error) in
            println(error)
        }
        XCTAssert(accounts?[0] == account, "Pass")
        
        // delete
        result = AMKeychain.deletePassword(SERVICE_NAME, account: account) {
            (error) in
            println(error)
        }
        XCTAssert(result, "Pass")
    }
    
    func testPasswordData() {
        // setPasswordData
        let NAME = "username"
        let PASS = "mypassword"
        let TOKEN = "mytoken"
        
        var result = false
        
        let dict : NSDictionary = ["name":NAME, "pass":PASS, "token":TOKEN]
        let data = NSKeyedArchiver.archivedDataWithRootObject(dict)
        result = AMKeychain.setPasswordData(SERVICE_NAME, account: account, data: data) {
            (error) in
            println(error)
        }
        XCTAssert(result, "Pass")
        
        // getPasswordData
        let myData = AMKeychain.getPasswordData(SERVICE_NAME, account: account) {
            (error) in
            println(error)
        }
        XCTAssertNotNil(myData, "Pass")
        if let myDict = NSKeyedUnarchiver.unarchiveObjectWithData(myData!) as? NSDictionary {
            switch (myDict["name"], myDict["pass"], myDict["token"]) {
            case (let name as String, let pass as String, let token as String):
                XCTAssert(name == NAME, "Pass")
                XCTAssert(pass == PASS, "Pass")
                XCTAssert(token == TOKEN, "Pass")
                break
            default:
                XCTAssert(false, "")
                break
            }
        } else {
            XCTAssert(false, "")
        }
        
        // delete
        result = AMKeychain.deletePassword(SERVICE_NAME, account: account) {
            (error) in
            println(error)
        }
        XCTAssert(result, "Pass")
    }
}
