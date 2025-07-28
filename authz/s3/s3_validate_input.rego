package validate.s3

errors[msg] {
    not input.method
    msg := "Missing HTTP method"
}

errors[msg] {
    not input.path
    msg := "Missing resource path"
}

errors[msg] {
    not input.headers["Authorization"]
    msg := "Missing Authorization header"
}

errors[msg] {
    not input.identity.accountId
    msg := "Missing identity.accountId"
}
