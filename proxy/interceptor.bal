import ballerina/http;
import ballerina/lang.value;

# Request interceptor to validate JWT and extract org_id
public service class JwtValidationInterceptor {
    *http:RequestInterceptor;

    isolated resource function 'default [string... path](http:RequestContext requestContext, http:Request request) 
            returns http:NextService|http:Response|error? {
        
        // Extract X-JWT-Assertion header
        string|http:HeaderNotFoundError jwtHeader = request.getHeader(headerName = "X-JWT-Assertion");
        
        if jwtHeader is http:HeaderNotFoundError {
            http:Response errorResponse = new;
            errorResponse.statusCode = 401;
            errorResponse.setTextPayload(payload = "X-JWT-Assertion header is required");
            return errorResponse;
        }

        // Parse JWT token to extract org_id
        string|error orgIdResult = self.extractOrgIdFromJwt(jwtToken = jwtHeader);
        
        if orgIdResult is error {
            http:Response errorResponse = new;
            errorResponse.statusCode = 401;
            errorResponse.setTextPayload(payload = "Invalid JWT token or org_id not found");
            return errorResponse;
        }

        // Store org_id in request context for use in service
        RequestContext context = {orgId: orgIdResult};
        requestContext.set(key = "requestContext", value = context);

        return requestContext.next();
    }

    # Extract org_id from JWT token
    # + jwtToken - JWT token string
    # + return - org_id claim or error
    private isolated function extractOrgIdFromJwt(string jwtToken) returns string|error {
        // Find the dots in JWT token to split it
        int? firstDotIndex = jwtToken.indexOf(substr = ".");
        if firstDotIndex is () {
            return error("Invalid JWT token format - no dots found");
        }
        
        int? secondDotIndex = jwtToken.indexOf(substr = ".", startIndex = firstDotIndex + 1);
        if secondDotIndex is () {
            return error("Invalid JWT token format - only one dot found");
        }

        // Extract payload part (between first and second dot)
        string payload = jwtToken.substring(startIndex = firstDotIndex + 1, endIndex = secondDotIndex);
        
        // Add padding if needed for base64 decoding
        string paddedPayload = self.addBase64Padding(base64String = payload);
        
        // For this example, we'll assume the payload is base64url encoded JSON
        // In a real implementation, you'd use proper JWT libraries
        byte[]|error decodedBytes = self.base64UrlDecode(encodedString = paddedPayload);
        
        if decodedBytes is error {
            return error("Failed to decode JWT payload");
        }

        string|error payloadString = string:fromBytes(bytes = decodedBytes);
        
        if payloadString is error {
            return error("Failed to convert payload to string");
        }

        // Parse JSON payload
        json|error jsonPayload = value:fromJsonString(str = payloadString);
        
        if jsonPayload is error {
            return error("Failed to parse JWT payload as JSON");
        }

        // Extract org_id claim
        JwtPayload|error jwtPayloadRecord = jsonPayload.cloneWithType(t = JwtPayload);
        
        if jwtPayloadRecord is error {
            return error("Failed to parse JWT payload structure");
        }

        string? orgId = jwtPayloadRecord.org_id;
        
        if orgId is () {
            return error("org_id claim not found in JWT token");
        }

        return orgId;
    }

    # Add padding to base64 string if needed
    # + base64String - Base64 string that might need padding
    # + return - Padded base64 string
    private isolated function addBase64Padding(string base64String) returns string {
        int remainder = base64String.length() % 4;
        if remainder == 0 {
            return base64String;
        }
        
        int paddingLength = 4 - remainder;
        string padding = "";
        int i = 0;
        while i < paddingLength {
            padding = padding + "=";
            i = i + 1;
        }
        
        return base64String + padding;
    }

    # Simple base64url decode (simplified implementation)
    # + encodedString - Base64url encoded string
    # + return - Decoded bytes or error
    private isolated function base64UrlDecode(string encodedString) returns byte[]|error {
        // Replace base64url characters with base64 characters
        string base64String = encodedString;
        
        // Replace - with +
        string tempString = "";
        int i = 0;
        while i < base64String.length() {
            string char = base64String.substring(startIndex = i, endIndex = i + 1);
            if char == "-" {
                tempString = tempString + "+";
            } else if char == "_" {
                tempString = tempString + "/";
            } else {
                tempString = tempString + char;
            }
            i = i + 1;
        }
        
        // For this example, we'll return the bytes representation
        // In a real scenario, you'd use proper base64 decoding
        return tempString.toBytes();
    }
}