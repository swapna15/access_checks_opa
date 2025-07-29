package authz.tests  # Use separate test package from policy

import data.authz.storage

# Test the allow rule with hardcoded valid input
test_allow_rule_exists if {
    not data.authz.storage.allow with input as {
        "action": "s3:GetObject",
        "user": {
            "type": "IAMUser",
            "role": "st-access-role"
        }
    }
}

test_aws_role_allowed if {
    data.authz.storage.allow with input as {
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::my-bucket/myfile.txt", 
        "user": {
            "name": "swapna", 
            "role": "st-access-role", 
            "type": "IAMUser"
        }
    }
    print("Allow:", data.authz.storage.allow)
}

test_azure_role_allowed if {
    data.authz.storage.allow with input as {
        "action": "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "resource": "/subscriptions/xxxx/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        "identity": {
            "type": "User",
            "claims": {
                "roles": [
                    "Reader",
                    "st-access-role"
                ],
                "name": "swapnakm15@gmail.com"
            }
        }
    }
}

test_role_denied_when_not_matched if {
    not data.authz.storage.allow with input as {
        "user": {
            "type": "IAMUser",
            "name": "bob",
            "role": "admin"
        }
    }
}
