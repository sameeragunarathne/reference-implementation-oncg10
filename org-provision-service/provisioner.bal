import ballerina/crypto;
import ballerina/http;
import ballerina/io;
import ballerina/lang.'string as strings;
import ballerina/log;
import ballerina/os;
import ballerina/lang.value;
import ballerina/time;

const string TOKEN_URL = "https://oauth2.googleapis.com/token";
const string HEALTHCARE_BASE_URL = "https://healthcare.googleapis.com/v1";
const string DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const int TOKEN_VALIDITY_SECONDS = 3600;

type ServiceAccount record {|
    string 'type;
    string project_id;
    string private_key_id;
    string private_key;
    string client_email;
    string client_id;
    string auth_uri;
    string token_uri;
    string auth_provider_x509_cert_url;
    string client_x509_cert_url;
    string? universe_domain;
|};

type AccessTokenResponse record {|
    string access_token;
    string token_type;
    int expires_in?;
    string scope?;
|};

type ErrorPayload record {|
    string 'error;
    json? details?;
|};

listener http:Listener provServiceListener = new (6000);

service / on provServiceListener {

    resource function post create\-fhir\-store(@http:Payload json payload) returns json|http:Response {
        if payload !is map<anydata> {
            return buildErrorResponse(400, "Expected JSON object payload");
        }

        map<anydata> data = payload;
        string|error projectId = getRequiredString(data, "project_id");
        if projectId is error {
            return buildErrorResponse(400, projectId.message());
        }

        string|error location = getRequiredString(data, "location");
        if location is error {
            return buildErrorResponse(400, location.message());
        }

        string|error datasetId = getRequiredString(data, "dataset_id");
        if datasetId is error {
            return buildErrorResponse(400, datasetId.message());
        }

        string|error storeId = getRequiredString(data, "store_id");
        if storeId is error {
            return buildErrorResponse(400, storeId.message());
        }

        string project = projectId;
        string loc = location;
        string dataset = datasetId;
        string store = storeId;

        var tokenResult = getGCPAccessToken();
        if tokenResult is error {
            log:printError("Failed to obtain Google Cloud access token", tokenResult);
            return buildErrorResponse(500, "Failed to obtain Google Cloud access token");
        }

        string accessToken = tokenResult;

        var createResult = createFhirStore(project, loc, dataset, store, accessToken);
        if createResult is error {
            log:printError("Google Cloud Healthcare API call failed", createResult);
            json? details = ();
            map<value:Cloneable> & readonly detail = createResult.detail();
            if detail is json {
                details = detail;
            }
            return buildErrorResponse(502, createResult.message(), details);
        }

        return createResult;
    }
}

function getGCPAccessToken() returns string|error {
    string? credentialsPath = os:getEnv("GOOGLE_APPLICATION_CREDENTIALS");
    if credentialsPath is () {
        return error("GOOGLE_APPLICATION_CREDENTIALS environment variable is not set");
    }
    
    json credsJson = check io:fileReadJson(credentialsPath);
    ServiceAccount serviceAccount = check credsJson.cloneWithType(ServiceAccount);

    time:Utc utc = time:utcNow();
    int currentUnixTime = utc[0];
    int expiryUnixTime = currentUnixTime + TOKEN_VALIDITY_SECONDS;

    json header = {
        "alg": "RS256",
        "typ": "JWT"
    };

    json claims = {
        "iss": serviceAccount.client_email,
        "scope": DEFAULT_SCOPE,
        "aud": TOKEN_URL,
        "iat": currentUnixTime,
        "exp": expiryUnixTime
    };

    string headerText = header.toJsonString();
    string claimsText = claims.toJsonString();

    string encodedHeader = toBase64Url(headerText.toBytes());
    string encodedClaims = toBase64Url(claimsText.toBytes());
    string signingInput = encodedHeader + "." + encodedClaims;

    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromContent(serviceAccount.private_key.toBytes());
    byte[] signature = check crypto:signRsaSha256(signingInput.toBytes(), privateKey);
    string encodedSignature = toBase64Url(signature);

    string jwtAssertion = signingInput + "." + encodedSignature;

    http:Client tokenClient = check new (TOKEN_URL);
    http:Request tokenRequest = new;
    tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
    tokenRequest.setPayload(string `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwtAssertion}`);

    http:Response tokenResponse = check tokenClient->post("", tokenRequest);
    json tokenJson = check tokenResponse.getJsonPayload();

    AccessTokenResponse tokenData = check tokenJson.cloneWithType(AccessTokenResponse);
    return tokenData.access_token;
}

function createFhirStore(string projectId, string location, string datasetId, string storeId, string accessToken)
returns json|error {
    string parent = string `/projects/${projectId}/locations/${location}/datasets/${datasetId}`;

    http:Client healthcareClient = check new (HEALTHCARE_BASE_URL);
    http:Request createRequest = new;
    json payload = {
        "version": "R4",
        "enableUpdateCreate": true
    };

    createRequest.setJsonPayload(payload);
    createRequest.setHeader("Authorization", string `Bearer ${accessToken}`);
    createRequest.setHeader("Content-Type", "application/json");

    string path = string `${parent}/fhirStores?fhirStoreId=${storeId}`;

    http:Response response = check healthcareClient->post(path, createRequest);
    if response.statusCode < 200 || response.statusCode >= 300 {
        json? details = ();
        var errorJson = response.getJsonPayload();
        if errorJson is json {
            details = errorJson;
        }
        return error(string `Google Cloud API returned status ${response.statusCode}`, details = details);
    }

    return check response.getJsonPayload();
}

function getRequiredString(map<anydata> payload, string 'field) returns string|error {
    anydata? value = payload['field];
    if value is string {
        string trimmed = strings:trim(value);
        if trimmed.length() > 0 {
            return trimmed;
        }
    }
    return error(string `Missing required field: ${'field}`);
}

function buildErrorResponse(int statusCode, string message, json? details = ()) returns http:Response {
    http:Response response = new;
    ErrorPayload errorPayload = {
        'error: message
    };
    if details is json {
        errorPayload.details = details;
    }

    response.setJsonPayload(errorPayload);
    response.statusCode = statusCode;
    return response;
}

function toBase64Url(byte[] bytes) returns string {
    string encoded = bytes.toBase64();
    byte[] encodedBytes = encoded.toBytes();
    byte[] result = [];
    foreach var b in encodedBytes {
        if b == 43 { // '+'
            result.push(45);
        } else if b == 47 { // '/'
            result.push(95);
        } else if b == 61 { // '=' padding
            continue;
        } else {
            result.push(b);
        }
    }
    return checkpanic strings:fromBytes(result);
}

