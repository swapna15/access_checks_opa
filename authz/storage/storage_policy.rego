package authz.storage

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
  print("Error count for s3 storage validation:", count(s3.errors))
  count(s3.errors) == 0
  print("S3 Role Match:", input_args.user.role == expected_role)
  input_args.user.role == expected_role 
  print("S3 Action check for delete:", input_args.action != "s3:DeleteObject")
  input_args.action != "s3:DeleteObject"
  print("Matched role for S3")
} else if {
  count(azure.errors) == 0
  print("Error count for Azure storage validation:", count(azure.errors))
  some i
  role := input_args.identity.claims.roles[i]
  print("Azure Role Match:", role)
  role == expected_role
  contains(input_args.action,"delete") == false
  print("Azure Action check for delete", contains(input_args.action,"delete"))
  print("Matched role for Azure claims at index", i, ":", input.identity.claims.roles[i])
}