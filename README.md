AMKeychain
==========
AMKeychain is wrapper for The Keychain on iOS.

Usage
==========
Add amkeychain.swift to your project.

Sample
==========
```swift
let serviceName = "MyService"
AMKeychain.setPassword(serviceName, account: "username", password: "userpass")
let pass = AMKeychain.getPassword(serviceName, account: "username")
println(pass)    // "userpass"

// display all accounts
let accounts = AMKeychain.getAccounts(serviceName)
for account in accounts! {
  println(account)   // "username"
}

AMKeychain.deletePassword(serviceName, account: "username")
```

Error handling
```swift
AMKeychain.setPassword(serviceName, account: "username", password: "userpass") {
    (error) in
    println(error)
}
```
