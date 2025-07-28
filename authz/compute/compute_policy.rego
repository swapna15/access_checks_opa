package authz.ec2

default ec2_allow = false

# Allow access only if user role is 'st-access-role'
allow if {
  print("Evaluating access for input:", input)
  get_user_role_ec2(input, "ec2-access-role")
}

# Extracts and verifies role from either AWS or Azure identity
get_user_role(input_args, expected_role) if {
  input_args.user.role == expected_role
  print("Matched role in input.user:", input.user.role)
} else if {
  some i
  input_args.identity.claims.roles[i] == expected_role
  print("Matched role in Azure claims at index", i, ":", input.identity.claims.roles[i])
} 
