# go-bcrypt
Password hasher and checker

### Installation
```go
go get github.com/mtdevs28080617/go-bcrypt
```

### Usage Example
##### Basic usage example
```go
b, err := go_bcrypt.NewBcrypt()

if err != nil {
	panic(err)
}

hashed, err := b.Hash("mypassword")

if err != nil {
	panic(err)
}

valid := b.Valid(hashed, "mypassword")
```

##### With custom example
```go
b, err := go_bcrypt.NewBcrypt(go_bcrypt.WithCustomCost(11))

if err != nil {
	panic(err)
}

hashed, err := b.Hash("mypassword")

if err != nil {
	panic(err)
}

valid := b.Valid(hashed, "mypassword")
```