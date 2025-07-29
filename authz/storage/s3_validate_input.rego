package validate.s3

errors[msg] if {
    print("S3 checks starts")
    not input.action
    msg := "Missing action"
}

errors[msg] if {
    not input.resource
    msg := "Missing resource path"
}

errors[msg] if {
    not input.user
    msg := "Missing user details"
}

errors[msg] if {
    print("S3 checks end")
    not input.user.role
    msg := "Missing user role"
}
