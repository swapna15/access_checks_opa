package authz.s3

import data.validate.azure
import data.validate.s3

default s3_allow = false
default s3_delete = false

# Allow access only if user role is 'st-access-role'
allow if {
  print("Evaluating access for input:", input)
  get_user_role(input, "st-access-role")
}

# Extracts and verifies role from either AWS or Azure identity
get_user_role(input_args, expected_role) if {
  print("Error Count:", count(s3.errors))
  count(s3.errors) == 0
  print("Role Match:", input_args.user.role == expected_role)
  input_args.user.role == expected_role 
  print("Action:", input_args.action != "s3:DeleteObject")
  input_args.action != "s3:DeleteObject"
  print("Matched role in input.user:", input.user.role)
} else if {
  count(azure.errors) == 0
  some i
  input_args.identity.claims.roles[i] == expected_role 
  input_args.identity.claims.roles[i].action != "delete"
  print("Matched role in Azure claims at index", i, ":", input.identity.claims.roles[i])
} 
