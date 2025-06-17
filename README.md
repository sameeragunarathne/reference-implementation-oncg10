# reference-implementation-oncg10
This repository provides a reference implementation for G10, demonstrating reference implementation for ONC's §170.315(g)(10) certification criteria.

## Version Information

- **Ballerina**: 2201.12.3

## Running the Ballerina Services

1. **Navigate to the Ballerina Project Directory**:

   ```bash
   cd reference-implementation-oncg10/<respective-service>
   ```

2. **Run the Ballerina Service**:

   ```bash
   bal run
   ```

   The service will start, typically listening on `http://localhost:9090`.

## Additional Notes
If you are using Asgardeo as the Identity Provider, use the script in resources/adaptive-authentication-script.js to 
validate audience claim during authentication. 
Refer https://wso2.com/asgardeo/docs/guides/authentication/conditional-auth/ to learn more on how to add 
conditional authentication.