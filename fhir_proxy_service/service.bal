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
    log:printDebug(string `Organization validation for org: ${orgNameStr}, request path: ${reqPath}`);

    string jwt = headers.hasKey(X_JWT_HEADER) ? headers.get(X_JWT_HEADER)[0] : "";

    if jwt == "" && publicEndpoints.indexOf(reqPath) > -1 {
        return validateOrgWithResolver(orgName);
    }

    if orgName is () || jwt == "" {
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
        OrgResolverResponse response = check orgResolverClient->/[orgName](validate = true, headers = { "api-key" :"eyJraWQiOiJnYXRld2F5X2NlcnRpZmljYXRlX2FsaWFzIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI0ZTA1N2FmZC1mNjg1LTQwNGUtYTI1Yy1hOGEzZGY4MzY5MGVAY2FyYm9uLnN1cGVyIiwiYXVkIjoiY2hvcmVvOmRlcGxveW1lbnQ6c2FuZGJveCIsIm9yZ2FuaXphdGlvbiI6eyJ1dWlkIjoiYzMyNjE4Y2YtMzg5ZC00NGYxLTkzZWUtYjY3YTM0NjhhYWUzIn0sImlzcyI6Imh0dHBzOlwvXC9zdHMuY2hvcmVvLmRldjo0NDNcL2FwaVwvYW1cL3B1Ymxpc2hlclwvdjJcL2FwaXNcL2ludGVybmFsLWtleSIsImtleXR5cGUiOiJTQU5EQk9YIiwic3Vic2NyaWJlZEFQSXMiOlt7InN1YnNjcmliZXJUZW5hbnREb21haW4iOm51bGwsIm5hbWUiOiJvcmctcmVzb2x2ZXItc2VydmljZSAtIFJlc29sdmVyIE9yZ3MiLCJjb250ZXh0IjoiXC9jMzI2MThjZi0zODlkLTQ0ZjEtOTNlZS1iNjdhMzQ2OGFhZTNcL2cxMC1jb21wbGlhbmNlXC9vcmctcmVzb2x2ZXItc2VydmljZVwvdjEuMCIsInB1Ymxpc2hlciI6ImNob3Jlb19wcm9kX2FwaW1fYWRtaW4iLCJ2ZXJzaW9uIjoidjEuMCIsInN1YnNjcmlwdGlvblRpZXIiOm51bGx9XSwiZXhwIjoxNzYyOTQwNjY2LCJ0b2tlbl90eXBlIjoiSW50ZXJuYWxLZXkiLCJpYXQiOjE3NjI5NDAwNjYsImp0aSI6IjBhMzkyNTFjLTNkYTctNDM3ZC1iODc1LTJjMzFhYjI5OWVjZCJ9.VBubT3OutfEbJHmTljLoDPXD57DvdtcMTfadA_7GTVjUbG0W0xeBy0JyOognuITL7g90NQv8TfRqeRYmU4GmDGAX1MdGgOFkRkkJ1wAUchotwEMbXMQhcbyAfmIL6ZaRv0wxIFraXqYtRLd_hvyIJIj5-i3AamjKaMICWs4aLqZp88TihQ_i8-JxXsO2vyVMDcetEWX279nNyIQY-5uUMAKTyDJxW6h1Fs9fBd9jQaDDSwOn4K-AMf4wMQ693uHd6W0lxESPCNjCtdLGmaIctrAELIxTHBGcQ_FAfMP33gNk4yaz-aZ93_Tj4xBccfMB8bs9NCU8aR_dj5P2eDJhW35YO7mysp7AKJo_WdI7Ltnlf4S3xzN07nICF5coe-d0LocYoikYRyWk2TL-EXze_cYGLVEYoEmqFP3DWNrOB85rxVRQNCCFnIhsPmOddUmLKEdzO68jaIy3BGJ2C8ciSZjz1OWOGPjvS5ql_BpgvKIRQ7JL1KQd3jm_KOGm0sG2mIsbV5pEHHyIj4bgfzmlKCWGebiQdu9wodik_2vmYSL3niz6-ZnAiDgGiI1OMkKM3TzKuI9Yhopn2bQhMNAtaeX4PB7clFkwTWKtYOJ1RfGm5pXa7nVB-YZf2CIE-x1EKB8q-D3SQotbkPpl16zyDX_m2N5pw15BV5IBKYakzQY" });

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
