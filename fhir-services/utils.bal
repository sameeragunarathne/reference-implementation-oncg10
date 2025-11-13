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

import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/jwt;
import ballerina/lang.'string as strings;
import ballerina/log;
import ballerina/url;
import ballerinax/health.clients.fhir as fhir;
import ballerinax/health.fhir.r4;
import ballerinax/health.fhir.r4.parser as fhirParser;

configurable ClinicFhirConnectorConfig clinicOrgConfig = ?;
configurable string clinicHeaderName = "x-clinic-name";

isolated map<fhir:FHIRConnector> fhirConnectorCache = {};
isolated map<ResolvedClinicConfig> resolvedClinicConfigCache = {};
isolated map<string> clinicConfigSignatures = {};
isolated map<string> clinicConnectorSignatures = {};
isolated map<http:Client> resolverClientCache = {};

type RemoteClinicConfig record {|
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyContent;
|};

type ResolvedClinicConfig record {|
    string baseURL;
    string tokenEndpoint;
    string clientId;
    string keyFilePath;
    boolean urlRewrite;
    string? replacementURL;
    boolean validateServerCapabilities;
|};

type ClinicFhirConnectorConfig record {|
    string resolverBaseUrl;
    string resolverPath = "/resolver/orgs";
    boolean urlRewrite = false;
    string? replacementURL = ();
    boolean validateServerCapabilities = false;
|};

isolated function getOrCreateResolverClient(string baseUrl) returns http:Client|error {
    lock {
        http:Client? existing = resolverClientCache[baseUrl];
        if existing is http:Client {
            return existing;
        }

        http:Client httpClient = check new (baseUrl);
        resolverClientCache[baseUrl] = httpClient;
        return httpClient;
    }
}

isolated function buildResolverRequestPath(string basePath, string clinicName) returns string|error {
    string sanitizedBase = basePath.endsWith("/") ? basePath.substring(0, basePath.length() - 1) : basePath;
    string encodedClinic = check url:encode(clinicName, "UTF-8");
    return string `${sanitizedBase}/${encodedClinic}`;
}

isolated function fetchRemoteClinicConfig(string clinicName, ClinicFhirConnectorConfig resolverConfig) returns RemoteClinicConfig|error {
    http:Client resolverClient = check getOrCreateResolverClient(resolverConfig.resolverBaseUrl);
    string requestPath = check buildResolverRequestPath(resolverConfig.resolverPath, clinicName);
    http:Response response = check resolverClient->get(requestPath);

    int statusCode = response.statusCode;
    if statusCode >= 400 {
        map<anydata> logProperties = {
            clinicName: clinicName,
            resolverBaseUrl: resolverConfig.resolverBaseUrl,
            resolverPath: resolverConfig.resolverPath,
            statusCode: statusCode
        };
        json|error errorPayload = response.getJsonPayload();
        if errorPayload is json {
            logProperties["body"] = errorPayload;
        }

        log:printError(string `Resolver service responded with status ${statusCode} for clinic ${clinicName}`,
                properties = logProperties);
        return error(string `Resolver service returned status ${statusCode}`);
    }

    json payload = check response.getJsonPayload();
    string baseURL = check extractNonEmptyString(payload, "baseURL");
    string tokenEndpoint = check extractNonEmptyString(payload, "tokenEndpoint");
    string clientId = check extractNonEmptyString(payload, "clientId");
    string rawKeyFile = check extractKeyFileField(payload);
    string keyContent = check ensureKeyFileContent(rawKeyFile);

    return {
        baseURL: baseURL,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        keyContent: keyContent
    };
}

isolated function buildConfigSignature(RemoteClinicConfig remoteConfig, ClinicFhirConnectorConfig clinicConfig) returns string {
    string replacement = clinicConfig.replacementURL is string ? <string>clinicConfig.replacementURL : "";
    return string `${remoteConfig.baseURL}|${remoteConfig.tokenEndpoint}|${remoteConfig.clientId}|${remoteConfig.keyContent}|${clinicConfig.urlRewrite}|${replacement}|${clinicConfig.validateServerCapabilities}`;
}

isolated function materializeKeyFile(string clinicName, string keyContent, string? reusePath) returns string|error {
    if reusePath is string && reusePath.length() > 0 {
        string existingPath = reusePath;
        error? rewriteResult = io:fileWriteString(existingPath, keyContent);
        if rewriteResult is () {
            return existingPath;
        }
        if rewriteResult is error {
            log:printWarn(string `Failed to reuse existing key file for clinic ${clinicName}`);
        }
    }

    string tempFilePath = check file:createTemp(prefix = string `g10_key_${clinicName}_`, suffix = ".pem");
    check io:fileWriteString(tempFilePath, keyContent);
    return tempFilePath;
}

isolated function getClinicResolverConfig(string clinicName) returns ClinicFhirConnectorConfig|error {
    ClinicFhirConnectorConfig config = clinicOrgConfig;
    string normalizedBase = strings:trim(config.resolverBaseUrl);
    if normalizedBase.length() == 0 {
        return error(string `Resolver base URL is empty for clinic ${clinicName}`);
    }

    if normalizedBase.endsWith("/") {
        normalizedBase = normalizedBase.substring(0, normalizedBase.length() - 1);
    }

    string configuredPath = strings:trim(config.resolverPath);
    if configuredPath.length() == 0 {
        configuredPath = "/resolver/orgs";
    }

    string normalizedPath = ensureLeadingSlash(configuredPath);

    return {
        resolverBaseUrl: normalizedBase,
        resolverPath: normalizedPath,
        urlRewrite: config.urlRewrite,
        replacementURL: config.replacementURL,
        validateServerCapabilities: config.validateServerCapabilities
    };
}

isolated function getResolvedClinicConfig(string clinicName) returns ResolvedClinicConfig|error {
    ClinicFhirConnectorConfig resolverConfig = check getClinicResolverConfig(clinicName);
    RemoteClinicConfig remoteConfig = check fetchRemoteClinicConfig(clinicName, resolverConfig);
    string signature = buildConfigSignature(remoteConfig, resolverConfig);
    string? reusePath = ();
    lock {
        ResolvedClinicConfig? cachedConfig = resolvedClinicConfigCache[clinicName];
        reusePath = cachedConfig is ResolvedClinicConfig ? cachedConfig.keyFilePath : ();
    }
    string keyFilePath = check materializeKeyFile(clinicName, remoteConfig.keyContent, reusePath);
    ResolvedClinicConfig resolvedConfig = {
        baseURL: remoteConfig.baseURL,
        tokenEndpoint: remoteConfig.tokenEndpoint,
        clientId: remoteConfig.clientId,
        keyFilePath: keyFilePath,
        urlRewrite: resolverConfig.urlRewrite,
        replacementURL: resolverConfig.replacementURL,
        validateServerCapabilities: resolverConfig.validateServerCapabilities
    };
    lock {
        resolvedClinicConfigCache[clinicName] = resolvedConfig.clone();
    }
    lock {
        clinicConfigSignatures[clinicName] = signature;
    }

    string? existingConnectorSignature = ();
    lock {
        existingConnectorSignature = clinicConnectorSignatures[clinicName];
    }
    if existingConnectorSignature is string && existingConnectorSignature != signature {
        lock {
            _ = fhirConnectorCache.remove(clinicName);
        }
        lock {
            _ = clinicConnectorSignatures.remove(clinicName);
        }
    }
    return resolvedConfig;
}

isolated function buildJwtAssertion(ResolvedClinicConfig resolvedConfig) returns string|error {
    jwt:IssuerConfig issuerConfig = {
        issuer: resolvedConfig.clientId,
        username: resolvedConfig.clientId,
        audience: resolvedConfig.tokenEndpoint,
        customClaims: {"scope": "https://www.googleapis.com/auth/cloud-platform"},
        expTime: 3600,
        signatureConfig: {
            config: {
                keyFile: resolvedConfig.keyFilePath
            }
        }
    };

    return check jwt:issue(issuerConfig);
}

isolated function getOrCreateFhirConnector(string clinicName) returns fhir:FHIRConnector|error {
    ResolvedClinicConfig resolvedConfig = check getResolvedClinicConfig(clinicName);
    string currentSignature = "";
    string? cachedSignature = ();
    lock {
        currentSignature = clinicConfigSignatures[clinicName] ?: "";
    }
    lock {
        cachedSignature = clinicConnectorSignatures[clinicName];
    }
    fhir:FHIRConnector? existing = ();
    lock {
        existing = fhirConnectorCache[clinicName];
    }
    if existing is fhir:FHIRConnector && cachedSignature is string && cachedSignature == currentSignature {
        return existing;
    }

    string jwtAssertion = check buildJwtAssertion(resolvedConfig);
    http:OAuth2JwtBearerGrantConfig oauthConfig = {
        tokenUrl: resolvedConfig.tokenEndpoint,
        assertion: jwtAssertion,
        clientId: resolvedConfig.clientId
    };

    fhir:FHIRConnectorConfig connectorConfig = {
        baseURL: resolvedConfig.baseURL,
        mimeType: fhir:FHIR_JSON,
        authConfig: oauthConfig,
        urlRewrite: resolvedConfig.urlRewrite,
        replacementURL: resolvedConfig.replacementURL
    };

    fhir:FHIRConnector connector = check new (connectorConfig,
        enableCapabilityStatementValidation = resolvedConfig.validateServerCapabilities
    );
    lock {
        fhirConnectorCache[clinicName] = connector;
    }
    lock {
        clinicConnectorSignatures[clinicName] = currentSignature;
    }
    log:printInfo(string `Initialized FHIR connector for clinic ${clinicName}`,
            properties = {clinicName: clinicName, baseURL: resolvedConfig.baseURL});
    return connector;
}

public isolated function getClinicNameFromContext(r4:FHIRContext fhirContext) returns string|r4:FHIRError {
    r4:HTTPRequest? httpRequest = fhirContext.getHTTPRequest();
    if httpRequest is () {
        return r4:createFHIRError("Clinic header is not available in the request", r4:ERROR, r4:PROCESSING,
                httpStatusCode = http:STATUS_BAD_REQUEST);
    }

    map<string[]> headers = <map<string[]>>httpRequest.headers.clone();
    string normalizedHeader = strings:toLowerAscii(strings:trim(clinicHeaderName));

    foreach string headerName in headers.keys() {
        string sanitizedName = strings:toLowerAscii(strings:trim(headerName));
        if sanitizedName == normalizedHeader {
            string[]? values = headers[headerName];
            if values is () {
                continue;
            }
            foreach string value in values {
                string trimmed = strings:trim(value);
                if trimmed.length() > 0 {
                    return trimmed;
                }
            }
            return r4:createFHIRError("Clinic header value is empty", r4:ERROR, r4:PROCESSING,
                    httpStatusCode = http:STATUS_BAD_REQUEST);
        }
    }

    return r4:createFHIRError(string `Clinic header '${clinicHeaderName}' is not present`, r4:ERROR, r4:PROCESSING,
            httpStatusCode = http:STATUS_BAD_REQUEST);
}

public isolated function getFhirConnectorForContext(r4:FHIRContext fhirContext) returns fhir:FHIRConnector|r4:FHIRError {
    string|r4:FHIRError clinicNameResult = getClinicNameFromContext(fhirContext);
    if clinicNameResult is r4:FHIRError {
        return clinicNameResult;
    }

    fhir:FHIRConnector|error connectorOrError = getOrCreateFhirConnector(clinicNameResult);
    if connectorOrError is fhir:FHIRConnector {
        return connectorOrError;
    }

    return r4:createFHIRError("Failed to initialize FHIR connector", r4:ERROR, r4:PROCESSING,
            diagnostic = connectorOrError.message(), cause = connectorOrError, httpStatusCode = http:STATUS_BAD_GATEWAY);
}

public isolated function buildSearchParameterMap(r4:FHIRContext fhirContext) returns map<string[]> {
    map<string[]> queryParameters = {};
    readonly & map<readonly & r4:RequestSearchParameter[]> requestParams = fhirContext.getRequestSearchParameters();

    foreach string paramName in requestParams.keys() {
        readonly & r4:RequestSearchParameter[]? paramArray = requestParams[paramName];
        if paramArray is () {
            continue;
        }
        string[] values = [];
        foreach readonly & r4:RequestSearchParameter param in paramArray {
            values.push(param.value);
        }
        if values.length() > 0 {
            queryParameters[paramName] = values;
        }
    }

    return queryParameters;
}

isolated function ensureJsonPayload(json|xml payload, string context) returns json|r4:FHIRError {
    if payload is json {
        return payload;
    }

    return r4:createFHIRError(string `FHIR server returned XML payload for ${context}`, r4:ERROR, r4:PROCESSING,
            httpStatusCode = http:STATUS_NOT_ACCEPTABLE);
}

isolated function handleConnectorError(r4:FHIRContext fhirContext, fhir:FHIRError connectorError)
        returns r4:OperationOutcome|r4:FHIRError|error {
    if connectorError is fhir:FHIRServerError {
        fhir:FHIRServerErrorDetails details = connectorError.detail();
        int statusCode = details.httpStatusCode;
        fhirContext.setResponseStatusCode(statusCode);

        json|xml resourcePayload = details.'resource;
        if resourcePayload is json {
            r4:OperationOutcome operationOutcome = check fhirParser:parse(resourcePayload, r4:OperationOutcome)
                .ensureType();
            return operationOutcome.clone();
        }
        string diagnostic = resourcePayload.toString();
        return r4:createFHIRError(connectorError.message(), r4:ERROR, r4:PROCESSING, diagnostic = diagnostic,
                cause = connectorError, httpStatusCode = statusCode);
    }

    fhirContext.setResponseStatusCode(http:STATUS_BAD_GATEWAY);
    return r4:createFHIRError(connectorError.message(), r4:ERROR, r4:PROCESSING, cause = connectorError,
            httpStatusCode = http:STATUS_BAD_GATEWAY);
}

public isolated function fetchResourceById(r4:FHIRContext fhirContext, string resourceType, string id,
        typedesc<anydata> resourceDescriptor = json)
        returns anydata|r4:OperationOutcome|r4:FHIRError|error {
    fhir:FHIRConnector|r4:FHIRError connectorResult = getFhirConnectorForContext(fhirContext);
    if connectorResult is r4:FHIRError {
        return connectorResult;
    }

    fhir:FHIRResponse|fhir:FHIRError response = connectorResult->getById(resourceType, id);
    if response is fhir:FHIRResponse {
        fhirContext.setResponseStatusCode(response.httpStatusCode);
        json|r4:FHIRError payloadOrError = ensureJsonPayload(response.'resource,
                string `${resourceType}/${id}`);
        if payloadOrError is r4:FHIRError {
            return payloadOrError;
        }
        anydata parsedResource = check fhirParser:parse(payloadOrError, resourceDescriptor).ensureType();
        return parsedResource.clone();
    }

    return check handleConnectorError(fhirContext, response);
}

public isolated function searchResourceBundle(r4:FHIRContext fhirContext, string resourceType,
        fhir:RequestMode mode = fhir:GET) returns r4:Bundle|r4:OperationOutcome|r4:FHIRError|error {
    fhir:FHIRConnector|r4:FHIRError connectorResult = getFhirConnectorForContext(fhirContext);
    if connectorResult is r4:FHIRError {
        return connectorResult;
    }

    map<string[]> queryParameters = buildSearchParameterMap(fhirContext);
    fhir:FHIRResponse|fhir:FHIRError response = connectorResult->search(resourceType, mode = mode,
        searchParameters = queryParameters);
    if response is fhir:FHIRResponse {
        fhirContext.setResponseStatusCode(response.httpStatusCode);
        json|r4:FHIRError payloadOrError = ensureJsonPayload(response.'resource, resourceType);
        if payloadOrError is r4:FHIRError {
            return payloadOrError;
        }
        r4:Bundle bundle = check fhirParser:parse(payloadOrError, r4:Bundle).ensureType();
        return bundle.clone();
    }

    return check handleConnectorError(fhirContext, response);
}

isolated function ensureLeadingSlash(string value) returns string {
    if value.startsWith("/") {
        return value;
    }
    return string `/${value}`;
}

isolated function isPemContent(string value) returns boolean {
    string normalized = strings:trim(value);
    boolean hasBegin = normalized.startsWith("-----BEGIN ");
    boolean hasEnd = strings:indexOf(normalized, "-----END ") != -1;
    return hasBegin && hasEnd;
}

isolated function ensureKeyFileContent(string rawKeyFile) returns string|error {
    string trimmedValue = strings:trim(rawKeyFile);
    if trimmedValue.length() == 0 {
        return error("Key content returned by resolver is empty");
    }

    if isPemContent(trimmedValue) {
        return trimmedValue;
    }

    return error("Key content returned by resolver is not in PEM format");
}

isolated function extractNonEmptyString(json payload, string fieldName) returns string|error {
    if payload is map<json> {
        json? value = payload[fieldName];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return trimmed;
            }
        }
    }

    return error(string `Missing or empty field '${fieldName}' in resolver response`);
}

isolated function extractKeyFileField(json payload) returns string|error {
    if payload is map<json> {
        json? value = payload["keyFile"];
        if value is string {
            string trimmed = strings:trim(value);
            if trimmed.length() > 0 {
                return trimmed;
            }
        }
    }

    return error("Missing or empty field 'keyFile' in resolver response");
}
