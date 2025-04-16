#!/bin/bash

echo "==================================================================="
echo "Running all BBS+ Credential Scenarios"
echo "==================================================================="

echo -e "\n\n=== Running main BBS+ example ==="
cd ..
go run main.go
cd credential_scenarios

echo -e "\n\n=== Running Healthcare Credentials example ==="
go run healthcare_credential.go

echo -e "\n\n=== Running Digital Identity example ==="
go run digital_identity.go

echo -e "\n\n=== Running Academic Credentials example ==="
go run academic_credentials.go

echo -e "\n\nAll examples completed successfully!"