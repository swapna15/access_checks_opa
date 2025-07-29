package validate.azure

errors[msg] if {
    print("Azure checks start")
    not input.identity.claims
    msg := "Missing claims"
}

errors[msg] if {
    count(input.identity.claims.roles) == 0
    msg := "Missing roles in claims"
}

errors[msg] if {
    not input.identity.type
    msg := "Missing identity type"
}

errors[msg] if {
    print("Azure checks end")
    not input.identity.claims.name
    msg := "Missing user or resource name claim"
}
