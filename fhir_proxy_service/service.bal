// Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/jwt;
import ballerina/log;

http:Client fhirClient = check new (fhirServerUrl);
http:Client asgClient = check new (asgServerUrl);
http:Client orgResolverClient = check new (orgResolverServiceUrl);

// Record to map the org resolver service response
type OrgResolverResponse record {|
    string orgId?;
    boolean valid = false;
    string message?;
|};

service / on new http:Listener(proxyServerPort) {

    resource function get [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {
        return handleRequest(httpRequest, orgName, path, "GET");
    }

    resource function post [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {
        if path[path.length() - 1] == "token" {
            // Redirect to ASG token endpoint
            string payload = check httpRequest.getTextPayload();
            map<string[]> headers = extractHeaders(httpRequest);
            http:Response|http:ClientError res = asgClient->post("oauth2/token", payload, headers);
            if res is http:Response && res.statusCode == 200 {

                log:printDebug("Modifying response payload in policyNameOut mediation policy");
                map<json> resPayload = check res.getJsonPayload().ensureType();
                resPayload["smart_style_url"] = "https://api.jsonbin.io/v3/qs/68f9f197ae596e708f25eeaa";
                resPayload["need_patient_banner"] = false;
                resPayload["patient"] = "b1abc7e8-6a50-40d5-9221-143ccb0f3ab1";
                res.setJsonPayload(resPayload);
            }
            return res;
        }
        return handleRequest(httpRequest, orgName, path, "POST");
    }

    resource function patch [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {
        return handleRequest(httpRequest, orgName, path, "PATCH");
    }

    resource function put [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {
        return handleRequest(httpRequest, orgName, path, "PUT");
    }

    resource function delete [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {
        return handleRequest(httpRequest, orgName, path, "DELETE");
    }
}

// Extract headers from HTTP request
function extractHeaders(http:Request httpRequest) returns map<string[]> {
    map<string[]> headers = {};
    foreach string headerName in httpRequest.getHeaderNames() {
        string[]|http:HeaderNotFoundError headerResult = httpRequest.getHeaders(headerName);
        if headerResult is string[] {
            headers[headerName] = headerResult;
        }
    }
    return headers;
}

// Validate organization from JWT and request headers
function isValidOrg(map<string[]> headers, string? orgName, string reqPath) returns boolean {
    string orgNameStr = orgName ?: "N/A";
    log:printDebug(string `Organization validation for org: ${orgNameStr}, request path: ${reqPath}, headers: ${headers.toString()}`);

    string jwt = headers.hasKey(X_JWT_HEADER) ? headers.get(X_JWT_HEADER)[0] : "";
    if jwt == "" && headers.hasKey(AUTHORIZATION_HEADER) {
        string authHeader = headers.get(AUTHORIZATION_HEADER)[0];
        if authHeader.startsWith("Bearer ") {
            jwt = authHeader.substring(7);
        }
    }

    if jwt == "" && publicEndpoints.indexOf(reqPath) > -1 {
        log:printDebug("Public endpoint accessed, validating organization with resolver.");
        return validateOrgWithResolver(orgName);
    }

    if orgName is () || jwt == "" {
        log:printDebug("Missing organization name or JWT token.");
        return false;
    }

    return validateOrgWithJWT(jwt, orgName);
}

// Create unauthorized response
isolated function createUnauthorizedResponse() returns http:Response {
    http:Response unauthorizedResponse = new;
    unauthorizedResponse.statusCode = 401;
    unauthorizedResponse.setJsonPayload({"error": "Unauthorized: Invalid organization"});
    return unauthorizedResponse;
}

// Common request handler to eliminate code duplication
function handleRequest(http:Request httpRequest, string orgName, string[] path, string method) returns http:Response|error {
    string reqPath = string:'join("/", ...path);

    // Extract headers
    map<string[]> headers = extractHeaders(httpRequest);

    // Validate organization
    boolean isOrgValid = isValidOrg(headers, orgName, reqPath);
    if !isOrgValid {
        log:printInfo(string `Invalid organization access attempt for org: ${orgName}`);
        return createUnauthorizedResponse();
    }

    // Add organization header
    headers[X_ORG_HEADER] = [orgName];

    // Make the appropriate HTTP call based on method
    match method {
        "GET" => {
            return fhirClient->get(reqPath, headers);
        }
        "DELETE" => {
            return fhirClient->delete(reqPath, headers);
        }
        "POST"|"PATCH"|"PUT" => {
            json payload = check httpRequest.getJsonPayload();
            match method {
                "POST" => {
                    return fhirClient->post(reqPath, payload, headers);
                }
                "PATCH" => {
                    return fhirClient->patch(reqPath, payload, headers);
                }
                "PUT" => {
                    return fhirClient->put(reqPath, payload, headers);
                }
                _ => {
                    http:Response methodNotAllowedResponse = new;
                    methodNotAllowedResponse.statusCode = 405;
                    methodNotAllowedResponse.setJsonPayload({"error": "Method Not Allowed"});
                    return methodNotAllowedResponse;
                }
            }
        }
        _ => {
            http:Response methodNotAllowedResponse = new;
            methodNotAllowedResponse.statusCode = 405;
            methodNotAllowedResponse.setJsonPayload({"error": "Method Not Allowed"});
            return methodNotAllowedResponse;
        }
    }
}

// Validate organization using org resolver service
function validateOrgWithResolver(string? orgName) returns boolean {
    if orgName is () {
        log:printDebug("No organization name provided for validation");
        return false;
    }

    do {
        OrgResolverResponse response = check orgResolverClient->/[orgName](validate = true);

        log:printDebug(string `Organization validation result for ${orgName}: ${response.valid.toString()}`);
        return response.valid;

    } on fail error e {
        log:printError(string `Error validating organization ${orgName}`, e);
        return false;
    }
}

// Validate organization using JWT token
isolated function validateOrgWithJWT(string jwt, string? orgName) returns boolean {
    [jwt:Header, jwt:Payload]|error [_, payload] = jwt:decode(jwt);

    if payload.hasKey(JWT_ORG_NAME_CLAIM) {
        string tokenOrgName = payload.get(JWT_ORG_NAME_CLAIM).toString();
        log:printDebug(string `Executing token based organization validation.`, tokenOrgName = tokenOrgName, resourceOrgName = orgName);
        return tokenOrgName == orgName;
    }
    return false;
}
