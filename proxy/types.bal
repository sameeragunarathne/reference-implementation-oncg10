# JWT payload structure
public type JwtPayload record {
    string org_id?;
    // Add other JWT claims as needed
    string sub?;
    string iss?;
    int exp?;
    int iat?;
};

# Context to pass org_id through the request
public type RequestContext record {
    string orgId;
};