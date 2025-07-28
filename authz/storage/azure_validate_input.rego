package validate.azure

errors[msg] if {
    not input.identity.claims.sub
    msg := "Missing 'sub' claim"
}

errors[msg] if {
    not input.identity.claims.aud
    msg := "Missing 'aud' claim"
}

errors[msg] if {
    not input.identity.claims.iss
    msg := "Missing 'iss' claim"
}

errors[msg] if {
    not input.identity.claims.roles
    msg := "Missing roles claim"
}
