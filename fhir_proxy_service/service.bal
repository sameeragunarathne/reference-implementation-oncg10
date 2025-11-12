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

service / on new http:Listener(proxyServerPort) {

    resource function get [string orgName]/[string... path](http:Request httpRequest) returns http:Response|error {

        string reqPath = string:'join("/", ...path);

        map<string[]> headers = {};
        foreach string headerName in httpRequest.getHeaderNames() {
            string[]|http:HeaderNotFoundError headerResult = httpRequest.getHeaders(headerName);
            if headerResult is string[] {
                headers[headerName] = headerResult;
            }
        }
        // org name validation
        boolean isOrgValid = isValidOrg(headers, orgName, reqPath);
        if !isOrgValid {
            log:printInfo("Invalid organization access attempt for org: " + orgName);
            http:Response unauthorizedResponse = new;
            unauthorizedResponse.statusCode = 401;
            unauthorizedResponse.setPayload("Unauthorized: Invalid organization");
            return unauthorizedResponse;
        }

        headers[X_ORG_HEADER] = [orgName];

        http:Response response = check fhirClient->get(path = reqPath,
                        headers = headers
                    );

        return response;
    }
}

// Validate organization from JWT and request headers
isolated function isValidOrg(map<string[]> headers, string? orgName, string reqPath) returns boolean {

    log:printDebug(string `Organization validation for org: ${orgName is string ? orgName : "N/A"}, request path: ${reqPath}`);
    string jwt = headers.hasKey(X_JWT_HEADER) ? headers.get(X_JWT_HEADER)[0] : "";

    if jwt == "" && publicEndpoints.indexOf(reqPath) > 0 {
        // public endpoint, validate using org resolver service and handle logic
        // todo change this to use dedicated endpoint
        // check orgResolverClient->/orgName;
        return true;
    }
    if orgName == () || jwt is "" {
        return false;
    }
    [jwt:Header, jwt:Payload]|error [_, payload] = jwt:decode(jwt);

    if payload is jwt:Payload && payload.hasKey(JWT_ORG_NAME_CLAIM) {
        string tokenOrgName = payload.get(JWT_ORG_NAME_CLAIM).toString();
        log:printDebug(string `Executing token based organization validation.`, tokenOrgName = tokenOrgName, resourceOrgName = orgName);
        return tokenOrgName == orgName;
    }

    return false;
}
