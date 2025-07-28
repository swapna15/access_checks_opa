package authz.s3

import data.validate.azure
import data.validate.s3

default s3_allow = false
default s3_delete = false

# Allow access only if user role is 'st-access-role'
allow if {
  not azure.errors[_]
  not s3.errors[_]
  validate.input.valid_input  # no validation errors
  print("Evaluating access for input:", input)
  get_user_role(input, "st-access-role")
}

# Extracts and verifies role from either AWS or Azure identity
get_user_role_s3(input_args, expected_role) if {
  input_args.user.role == expected_role && input_args_user.action != delete
  print("Matched role in input.user:", input.user.role)
} else if {
  some i
  input_args.identity.claims.roles[i] == expected_role && input_args.identity.claims.roles[i].action != delete
  print("Matched role in Azure claims at index", i, ":", input.identity.claims.roles[i])
} 
