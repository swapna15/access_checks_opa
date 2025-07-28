package validate.input

default valid_input = false

valid_input {
    input.user
    input.user.id
    input.user.role
    input.resource
    input.resource.type
    input.resource.id
    input.action
}

valid_input {
    input.action
    input.resource
    input.identity
    input.identity.type
    input.identity.claims
    input.identity.claims.roles
    input.identity.claims.name
}