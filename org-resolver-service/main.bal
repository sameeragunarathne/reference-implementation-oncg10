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
import ballerina/lang.'string as strings;
import ballerina/log;
import ballerina/sql;
import ballerinax/mysql;
import ballerinax/mysql.driver as _;

configurable int servicePort = 8090;
configurable string remoteApiBaseUrl = ?;
configurable string remoteApiResourcePath = "/configs";

configurable string dbHost = ?;
configurable int dbPort = 3306;
configurable string dbUser = ?;
configurable string dbPassword = ?;
configurable string dbName = ?;

listener http:Listener httpListener = new (servicePort);

final http:Client remoteConfigClient = checkpanic new (remoteApiBaseUrl, {
        timeout: 20,
        httpVersion: http:HTTP_1_1
    });

final mysql:Client dbClient = checkpanic new (dbHost, dbUser, dbPassword, dbName, dbPort);

type FhirStoreConfig record {|
    string orgId;
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyFile;
|};

type ConfigResponse record {|
    string orgId;
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyFile;
|};

type DbConfigRow record {|
    string base_url;
    string token_endpoint;
    string client_id;
    string key_file;
|};

function init() returns error? {
    check initSchema();
}

service /resolver/orgs on httpListener {

    resource function get [string orgId](http:Request req) returns ConfigResponse|http:InternalServerError {
        boolean forceRefresh = false;
        string? refreshParam = req.getQueryParamValue("refresh");
        if refreshParam is string {
            forceRefresh = strings:toLowerAscii(strings:trim(refreshParam)) == "true";
        }

        FhirStoreConfig|error configResult = getOrFetchConfig(orgId, forceRefresh);
        if configResult is FhirStoreConfig {
            return toConfigResponse(configResult);
        }

        log:printError(string `Failed to retrieve FHIR configuration for org ${orgId}`,
            'error = configResult);
        return errorResponse("Failed to retrieve configuration");
    }

    resource function post .(http:Request req)
            returns ConfigResponse|http:BadRequest|http:Conflict|http:InternalServerError {
        json|error payloadResult = req.getJsonPayload();
        if payloadResult is error {
            log:printError("Failed to read configuration payload for create request",
                'error = payloadResult);
            return badRequestResponse("Invalid configuration payload");
        }

        json payload = payloadResult;
        string|error orgIdResult = extractNonEmptyString(payload, "orgId");
        if orgIdResult is error {
            log:printError("Missing organization id in configuration payload",
                'error = orgIdResult);
            return badRequestResponse("Missing organization identifier");
        }

        string orgId = orgIdResult;
        FhirStoreConfig|error? existingResult = getConfigFromDb(orgId);
        if existingResult is error {
            log:printError(string `Failed to verify existing configuration before creating for org ${orgId}`,
                'error = existingResult);
            return errorResponse("Failed to create configuration");
        } else if existingResult is FhirStoreConfig {
            return conflictResponse("FHIR configuration already exists for the organization");
        }

        FhirStoreConfig|error parsedConfigResult = parseConfigPayload(orgId, payload);
        if parsedConfigResult is FhirStoreConfig {
            error? persistResult = upsertConfig(parsedConfigResult);
            if persistResult is error {
                log:printError(string `Failed to persist configuration for org ${orgId}`,
                    'error = persistResult);
                return errorResponse("Failed to create configuration");
            }

            return toConfigResponse(parsedConfigResult);
        }

        log:printError(string `Configuration payload validation failed for org ${orgId}`,
            'error = parsedConfigResult);
        return badRequestResponse("Invalid configuration payload");
    }

    resource function put [string orgId](http:Request req)
            returns ConfigResponse|http:BadRequest|http:NotFound|http:InternalServerError {
        FhirStoreConfig|error? existingResult = getConfigFromDb(orgId);
        if existingResult is error {
            log:printError(string `Failed to retrieve existing configuration for update for org ${orgId}`,
                'error = existingResult);
            return errorResponse("Failed to update configuration");
        } else if existingResult is () {
            return notFoundResponse("FHIR configuration not found for the organization");
        }

        json|error payloadResult = req.getJsonPayload();
        if payloadResult is error {
            log:printError(string `Failed to read configuration payload for org ${orgId}`,
                'error = payloadResult);
            return badRequestResponse("Invalid configuration payload");
        }

        FhirStoreConfig|error parsedConfigResult = parseConfigPayload(orgId, payloadResult);
        if parsedConfigResult is FhirStoreConfig {
            error? persistResult = upsertConfig(parsedConfigResult);
            if persistResult is error {
                log:printError(string `Failed to persist configuration for org ${orgId}`,
                    'error = persistResult);
                return errorResponse("Failed to update configuration");
            }

            return toConfigResponse(parsedConfigResult);
        }

        log:printError(string `Configuration payload validation failed for org ${orgId}`,
            'error = parsedConfigResult);
        return badRequestResponse("Invalid configuration payload");
    }
}

function getOrFetchConfig(string orgId, boolean forceRefresh) returns FhirStoreConfig|error {
    FhirStoreConfig|error fetchResult = fetchAndPersistConfig(orgId);
    if fetchResult is FhirStoreConfig {
        return fetchResult;
    }

    error fetchError = fetchResult;
    log:printError(string `Failed to fetch configuration from remote API for org ${orgId}`,
        'error = fetchError);

    if !forceRefresh {
        FhirStoreConfig? existing = check getConfigFromDb(orgId);
        if existing is FhirStoreConfig {
            log:printError(string `Returning cached configuration for org ${orgId} due to remote API failure`,
                'error = fetchError);
            return existing;
        }
    }

    return fetchError;
}

function fetchAndPersistConfig(string orgId) returns FhirStoreConfig|error {
    FhirStoreConfig config = check fetchConfigFromApi(orgId);
    check upsertConfig(config);
    return config;
}

function parseConfigPayload(string orgId, json payload) returns FhirStoreConfig|error {
    string baseURL = check extractNonEmptyString(payload, "baseURL");
    string tokenEndpoint = check extractNonEmptyString(payload, "tokenEndpoint");
    string clientId = check extractNonEmptyString(payload, "clientId");
    string rawKeyFile = check extractKeyFileField(payload);
    string keyFile = check ensureKeyFileContent(rawKeyFile);

    return {
        orgId: orgId,
        baseURL: baseURL,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        keyFile: keyFile
    };
}

function fetchConfigFromApi(string orgId) returns FhirStoreConfig|error {
    string resourcePath = buildRemoteResourcePath(orgId);
    http:Response response = check remoteConfigClient->get(resourcePath);

    int statusCode = response.statusCode;
    if statusCode >= 400 {
        map<anydata> logProps = {
            orgId: orgId,
            statusCode: statusCode,
            path: resourcePath
        };
        json|error errorBody = response.getJsonPayload();
        if errorBody is json {
            logProps["responseBody"] = errorBody;
        } else if errorBody is error {
            log:printError(string `Failed to parse error payload from remote API for org ${orgId}`,
                'error = errorBody);
        }

        log:printError(string `Remote API responded with status ${statusCode} for org ${orgId}`,
            properties = logProps);
        return error(string `Remote API returned ${statusCode}`);
    }

    json payload = check response.getJsonPayload();
    string baseURL = check extractNonEmptyString(payload, "baseURL");
    string tokenEndpoint = check extractNonEmptyString(payload, "tokenEndpoint");
    string clientId = check extractNonEmptyString(payload, "clientId");
    string rawKeyFile = check extractKeyFileField(payload);
    string keyFile = check ensureKeyFileContent(rawKeyFile);

    return {
        orgId: orgId,
        baseURL: baseURL,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        keyFile: keyFile
    };
}

function getConfigFromDb(string orgId) returns FhirStoreConfig|error? {
    DbConfigRow|sql:Error rowResult = dbClient->queryRow(`SELECT base_url, token_endpoint, client_id, key_file
        FROM org_mapping WHERE org_id = ${orgId}`, DbConfigRow);

    if rowResult is DbConfigRow {
        FhirStoreConfig config = {
            orgId: orgId,
            baseURL: rowResult.base_url,
            tokenEndpoint: rowResult.token_endpoint,
            clientId: rowResult.client_id,
            keyFile: rowResult.key_file
        };
        return normalizeStoredKeyFile(config);
    } else if rowResult is sql:NoRowsError {
        return ();
    }

    return <error>rowResult;
}

function upsertConfig(FhirStoreConfig config) returns error? {
    _ = check dbClient->execute(`INSERT INTO org_mapping (org_id, base_url, token_endpoint, client_id, key_file)
        VALUES (${config.orgId}, ${config.baseURL}, ${config.tokenEndpoint}, ${config.clientId}, ${config.keyFile})
        ON DUPLICATE KEY UPDATE base_url = VALUES(base_url), token_endpoint = VALUES(token_endpoint),
            client_id = VALUES(client_id), key_file = VALUES(key_file)`);
}

function initSchema() returns error? {
    _ = check dbClient->execute(`CREATE TABLE IF NOT EXISTS org_mapping (
            org_id VARCHAR(128) PRIMARY KEY,
            base_url TEXT NOT NULL,
            token_endpoint TEXT NOT NULL,
            client_id TEXT NOT NULL,
            key_file LONGTEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )`);
}

function buildRemoteResourcePath(string orgId) returns string {
    string sanitizedBase = strings:trim(remoteApiResourcePath);
    if sanitizedBase == "" {
        sanitizedBase = "/resolver/orgs";
    }

    if sanitizedBase.endsWith("/") {
        return sanitizedBase + orgId;
    } else {
        return sanitizedBase + "/" + orgId;
    }
}

function extractNonEmptyString(json payload, string fieldName) returns string|error {
    if payload is map<json> {
        json? value = payload[fieldName];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return trimmed;
            }
        }
    }

    return error(string `Missing or empty field '${fieldName}' in remote API response`);
}

function extractKeyFileField(json payload) returns string|error {
    if payload is map<json> {
        json? value = payload["keyFile"];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return value;
            }
        }
    }

    return error("Missing or empty field 'keyFile' in remote API response");
}

function ensureKeyFileContent(string rawKeyFile) returns string|error {
    string trimmedValue = strings:trim(rawKeyFile);
    if trimmedValue.length() == 0 {
        return error("Key file value is empty");
    }

    if isPemContent(trimmedValue) {
        return trimmedValue;
    }

    return error("Key file value must contain PEM formatted content");
}

function isPemContent(string value) returns boolean {
    string normalized = strings:trim(value);
    boolean hasBegin = strings:indexOf(normalized, "-----BEGIN ") != -1;
    boolean hasEnd = strings:indexOf(normalized, "-----END ") != -1;
    return hasBegin && hasEnd;
}

function normalizeStoredKeyFile(FhirStoreConfig config) returns FhirStoreConfig|error {
    string resolvedKeyFile = check ensureKeyFileContent(config.keyFile);
    if resolvedKeyFile != config.keyFile {
        FhirStoreConfig updated = {
            orgId: config.orgId,
            baseURL: config.baseURL,
            tokenEndpoint: config.tokenEndpoint,
            clientId: config.clientId,
            keyFile: resolvedKeyFile
        };
        check upsertConfig(updated);
        return updated;
    }

    return config;
}

function toConfigResponse(FhirStoreConfig config) returns ConfigResponse {
    return {
        orgId: config.orgId,
        baseURL: config.baseURL,
        tokenEndpoint: config.tokenEndpoint,
        clientId: config.clientId,
        keyFile: config.keyFile
    };
}

function errorResponse(string message) returns http:InternalServerError {
    return {
        body: {message: message}
    };
}

function badRequestResponse(string message) returns http:BadRequest {
    return {
        body: {message: message}
    };
}

function conflictResponse(string message) returns http:Conflict {
    return {
        body: {message: message}
    };
}

function notFoundResponse(string message) returns http:NotFound {
    return {
        body: {message: message}
    };
}
