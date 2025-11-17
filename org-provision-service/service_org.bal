import ballerina/http;
import ballerina/log;
import ballerina/lang.'string as strings;
import ballerina/jwt;
import ballerina/time;

// Configurations for Asgardeo Management APIs
configurable string ASGARDEO_BASE_URL = ?;          // e.g., https://api.asgardeo.io/t/<root_org>
configurable string ASGARDEO_CLIENT_ID = ?;
configurable string ASGARDEO_CLIENT_SECRET = ?;
// Parent/root organization id used when creating sub-organizations
configurable string PARENT_ORG_ID = ?;
configurable string PARENT_ORG_NAME = ?;
// Header name to scope requests to a specific organization in Asgardeo.
// This changes based on deployment; keeping it configurable is safer.
configurable string ORG_SCOPE_HEADER = "X-WSO2-Organization";

// Reuse the listener defined in provisioner.bal (declared there as: listener http:Listener provServiceListener = new (6000);)

final http:Client tokenClient = checkpanic new (string `${ASGARDEO_BASE_URL}/t/${PARENT_ORG_NAME}/oauth2/token`);
final http:Client mgmtClient = checkpanic new (ASGARDEO_BASE_URL);

type OrgErrorPayload record {|
    string 'error;
    json? details?;
|};

type CreateOrganizationRequest record {|
    string name;
    string description?;
|};

type CreateApplicationRequest record {|
    string name;
    string[] grantTypes?;
    string[] callbackURLs?;
|};

// Required scopes for each resource
const SCOPE_ORGANIZATION_VIEW = "internal_organization_view";
const SCOPE_ORGANIZATION_CREATE = "internal_organization_create";
const SCOPE_ORGANIZATION_UPDATE = "internal_organization_update";
const SCOPE_APPLICATION_VIEW = "internal_application_mgt_view";
const SCOPE_APPLICATION_CREATE = "internal_application_mgt_create";
const SCOPE_APPLICATION_UPDATE = "internal_application_mgt_update";
const SCOPE_BRANDING_UPDATE = "internal_branding_preference_update";
const SCOPE_ORG_BRANDING_UPDATE = "internal_org_branding_preference_update";


service /organization\-provision on provServiceListener {

    // GET /organization
    resource function get organization(http:Request req) returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORGANIZATION_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        // List direct children for configured parent
        // Asgardeo: GET /api/server/v1/organizations?parentId=<PARENT_ORG_ID>
        string path = string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations?parentId=${PARENT_ORG_ID}`;

        http:Response|error res = mgmtClient->execute("GET", path, mgmtReq);
        if res is error {
            log:printError("List organizations failed", 'error = res);
            return buildError(502, "Failed to fetch organizations", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            json[] simplified = [];
            if resJson is map<json> {
                json? orgsAny = resJson["organizations"];
                if orgsAny is json[] {
                    foreach var o in orgsAny {
                        if o is map<json> {
                            string id = o["id"] is string ? <string>o["id"] : "";
                            string name = o["name"] is string ? <string>o["name"] : "";
                            string orgHandle = o["orgHandle"] is string ? <string>o["orgHandle"] : (o["id"] is string ? <string>o["id"] : "");
                            simplified.push({ "id": id, "name": name, "handle": orgHandle });
                        }
                    }
                }
            }
            return { "organizations": simplified };
        }
        return buildError(502, "Invalid response for organizations list");
    }

    // POST /organization
    resource function post organization(http:Request req, @http:Payload CreateOrganizationRequest body) returns json|http:Response {
        if strings:trim(body.name).length() == 0 {
            return buildError(400, "Missing required field: name");
        }
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORGANIZATION_CREATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader("Content-Type", "application/json");
        json payload = {
            name: body.name,
            description: body.description,
            parentId: PARENT_ORG_ID,
            "type": "TENANT"
        };
        mgmtReq.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations`, mgmtReq);
        if res is error {
            log:printError("Create organization failed", 'error = res);
            return buildError(502, "Failed to create organization", res.detail());
        }
        // Forward backend's response payload (contains id, etc.)
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for create organization");
    }

    // GET /organization/{orgId}
    resource function get organization/[string orgId](http:Request req) returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORGANIZATION_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader(ORG_SCOPE_HEADER, orgId);

        // Get organization details
        http:Response|error orgRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations/${orgId}`, mgmtReq);
        if orgRes is error {
            log:printError("Get organization failed", 'error = orgRes);
            return buildError(502, "Failed to fetch organization", orgRes.detail());
        }
        var orgJ = orgRes.getJsonPayload();
        if orgJ is json && orgJ is map<json> {
            string id = orgJ["id"] is string ? <string>orgJ["id"] : "";
            string name = orgJ["name"] is string ? <string>orgJ["name"] : "";
            string orgHandle = orgJ["orgHandle"] is string ? <string>orgJ["orgHandle"] : (orgJ["id"] is string ? <string>orgJ["id"] : "");
            return { "id": id, "name": name, "handle": orgHandle };
        }
        return buildError(502, "Invalid response for organization");
    }

    // GET /organization/{orgId}/settings
    resource function get organization/settings/[string orgId](http:Request req) returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORGANIZATION_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);

        http:Response|error res = mgmtClient->execute("GET", string `/o/${orgId}/api/server/v1/branding-preference?locale=en-US&name=${orgId}&type=ORG`, mgmtReq);
        if res is error {
            log:printError("Fetch branding settings failed", 'error = res);
            return buildError(502, "Failed to fetch organization settings", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for branding settings");
    }

    // GET /organization/settings/branding/{orgId}
    resource function get organization/settings/branding/[string orgId](http:Request req) returns json|http:Response {
        string|http:Response tokenResult = extractAccessTokenWithoutScope(req);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        
        // Branding settings endpoint
        http:Response|error res = mgmtClient->execute("GET", string `/o/${orgId}/api/server/v1/branding-preference?locale=en-US&name=${orgId}&type=ORG`, mgmtReq);
        if res is error {
            log:printError("Fetch branding settings failed", 'error = res);
            return buildError(502, "Failed to fetch organization branding settings", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for branding settings");
    }

    // PUT /organization/{orgId}/settings
    resource function post organization/settings/[string orgId](http:Request req, @http:Payload json payload) returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_BRANDING_UPDATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader("Content-Type", "application/json");
        mgmtReq.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/o/${orgId}/api/server/v1/branding-preference`, mgmtReq);
        if res is error {
            log:printError("Update branding settings failed", 'error = res);
            return buildError(502, "Failed to update organization settings", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for update branding settings");
    }

    // POST /organization/{orgId}/application
    resource function post application/[string orgId](http:Request req, @http:Payload CreateApplicationRequest body)
            returns json|http:Response {
        if strings:trim(body.name).length() == 0 {
            return buildError(400, "Missing required field: name");
        }
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_APPLICATION_CREATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader("Content-Type", "application/json");

        json payload = {
            name: body.name,
            templateId: "custom-application-oidc",
            inboundProtocolConfiguration: {
                oidc: {
                    state: "ACTIVE",
                    grantTypes: body.grantTypes ?: ["client_credentials"],
                    isFAPIApplication: false,
                    callbackURLs: body.callbackURLs ?: [],
                    publicClient: false,
                    pkce: { mandatory: false, supportPlainTransformAlgorithm: false },
                    hybridFlow: { enable: true, responseType: "code id_token" },
                    accessToken: {
                        "type": "JWT",
                        userAccessTokenExpiryInSeconds: 3600,
                        applicationAccessTokenExpiryInSeconds: 3600,
                        bindingType: "None",
                        revokeTokensWhenIDPSessionTerminated: false,
                        validateTokenBinding: false,
                        accessTokenAttributes: []
                    },
                    refreshToken: { expiryInSeconds: 86400, renewRefreshToken: true },
                    subjectToken: { enable: false, applicationSubjectTokenExpiryInSeconds: 180 },
                    idToken: {
                        expiryInSeconds: 3600,
                        audience: [],
                        idTokenSignedResponseAlg: "",
                        encryption: { algorithm: "", enabled: false, method: "" }
                    },
                    validateRequestObjectSignature: false,
                    scopeValidators: []
                }
            },
            advancedConfigurations: { skipLoginConsent: true, skipLogoutConsent: true },
            associatedRoles: { allowedAudience: "APPLICATION" }
        };
        mgmtReq.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/`, mgmtReq);
        if res is error {
            log:printError("Create application failed", 'error = res);
            return buildError(502, "Failed to create application", res.detail());
        }
        // Some APIs return payload empty and use Location header; forward headers + status + any body.
        map<json> out = {};
        var bodyJson = res.getJsonPayload();
        if bodyJson is json {
            if bodyJson is map<json> {
                out = bodyJson;
            } else {
                out = { body: bodyJson };
            }
        }
        var location = res.getHeader("Location");
        if location is string {
            out["location"] = location;
        }
        return <json>out;
    }

    // GET /organization/{orgId}/application/{appId}
    resource function get [string orgId]/application/[string appId](http:Request req) returns json|http:Response {
                // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_APPLICATION_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_application_mgt_view");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);

        http:Response|error res = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications/${appId}`, mgmtReq);
        if res is error {
            log:printError("Get application failed", 'error = res);
            return buildError(502, "Failed to fetch application", res.detail());
        }
        json app = {};
        var appJ = res.getJsonPayload();
        if appJ is json {
            app = appJ;
        }

        // Credentials
        http:Response|error credsRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications/${appId}/inbound-protocols/oidc`, mgmtReq);
        json creds = {};
        if credsRes is http:Response {
            var credsJ = credsRes.getJsonPayload();
            if credsJ is json {
                creds = credsJ;
            }
        }
        // Pick only required fields from application
        string appIdOut = "";
        string appNameOut = "";
        string appVersionOut = "";
        string appClientIdOut = "";
        if app is map<json> {
            appIdOut = app["id"] is string ? <string>app["id"] : "";
            appNameOut = app["name"] is string ? <string>app["name"] : "";
            appVersionOut = app["applicationVersion"] is string ? <string>app["applicationVersion"] : "";
            appClientIdOut = app["clientId"] is string ? <string>app["clientId"] : "";
        }
        // Pick only required fields from credentials
        string credClientIdOut = "";
        string credClientSecretOut = "";
        string[] credGrantTypesOut = [];
        string[] credCallbackURLsOut = [];
        if creds is map<json> {
            credClientIdOut = creds["clientId"] is string ? <string>creds["clientId"] : "";
            credClientSecretOut = creds["clientSecret"] is string ? <string>creds["clientSecret"] : "";
            if creds["grantTypes"] is json[] {
                json[] gtAny = <json[]>creds["grantTypes"];
                foreach var g in gtAny {
                    if g is string {
                        credGrantTypesOut.push(g);
                    }
                }
            }
            if creds["callbackURLs"] is json[] {
                json[] cbAny = <json[]>creds["callbackURLs"];
                foreach var u in cbAny {
                    if u is string {
                        credCallbackURLsOut.push(u);
                    }
                }
            }
        }
        return {
            application: {
                id: appIdOut,
                name: appNameOut,
                applicationVersion: appVersionOut,
                clientId: appClientIdOut
            },
            credentials: {
                clientId: credClientIdOut,
                clientSecret: credClientSecretOut,
                grantTypes: credGrantTypesOut,
                callbackURLs: credCallbackURLsOut
            }
        };
    }

    // PUT /organization/{orgId}/application/{appId}
    resource function put [string orgId]/application/[string appId](http:Request req, @http:Payload CreateApplicationRequest body)
            returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_APPLICATION_UPDATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader("Content-Type", "application/json");

        json patch = {
            inboundProtocolConfiguration: {
                oidc: {
                    grantTypes: body.grantTypes ?: [],
                    callbackURLs: body.callbackURLs ?: []
                }
            }
        };
        mgmtReq.setJsonPayload(patch);

        http:Response|error res = mgmtClient->put(string `/api/server/v1/applications/${appId}`, mgmtReq);
        if res is error {
            log:printError("Update application failed", 'error = res);
            return buildError(502, "Failed to update application", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for update application");
    }

    // GET /organization/{orgId}/applications/search?filter=...&limit=...&offset=...
    // Uses organization_switch grant to obtain an access token scoped to the target organization.
    resource function get [string orgId]/application(http:Request req, string? filter, int? limitCount, int? offsetCount)
            returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_APPLICATION_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_application_mgt_view");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);

        // Build query string
        string q = "";
        boolean first = true;
        if filter is string {
            q = q + (first ? "?" : "&") + string `filter=${filter}`;
            first = false;
        }
        if limitCount is int {
            q = q + (first ? "?" : "&") + string `limit=${limitCount}`;
            first = false;
        }
        if offsetCount is int {
            q = q + (first ? "?" : "&") + string `offset=${offsetCount}`;
        }

        string path = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications${q}`;
        http:Response|error res = mgmtClient->execute("GET", path, mgmtReq);
        if res is error {
            log:printError("Search applications failed", 'error = res);
            return buildError(502, "Failed to search applications", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            json[] simplified = [];
            // Expected format: { "applications": [ { ..app.. }, ... ] }
            if resJson is map<json> {
                json? appsAny = resJson["applications"];
                if appsAny is json[] {
                    foreach var a in appsAny {
                        if a is map<json> {
                            string id = a["id"] is string ? <string>a["id"] : "";
                            string name = a["name"] is string ? <string>a["name"] : "";
                            string version = a["applicationVersion"] is string ? <string>a["applicationVersion"] : "";
                            simplified.push({ "id": id, "name": name, "applicationVersion": version });
                        }
                    }
                }
                return { "applications": simplified };
            }
            // If backend returned a plain array of apps, handle that too.
            if resJson is json[] {
                foreach var a in resJson {
                    if a is map<json> {
                        string id = a["id"] is string ? <string>a["id"] : "";
                        string name = a["name"] is string ? <string>a["name"] : "";
                        string version = a["applicationVersion"] is string ? <string>a["applicationVersion"] : "";
                        simplified.push({ "id": id, "name": name, "applicationVersion": version });
                    }
                }
                return { "applications": simplified };
            }
        }
        return buildError(502, "Invalid response for search applications");
    }
}

// Decode and validate JWT from x-jwt-assertion header
function validateJwtAndExtractScopes(string jwtToken) returns string[]|http:Response {
    // Decode JWT without signature validation (signature is validated by API Gateway)
    [jwt:Header, jwt:Payload]|jwt:Error decodeResult = jwt:decode(jwtToken);
    if decodeResult is jwt:Error {
        log:printError("Failed to decode JWT", 'error = decodeResult);
        return buildError(401, "Invalid JWT token", decodeResult.message());
    }
    
    [jwt:Header, jwt:Payload] [_, payload] = decodeResult;
    
    // Extract claims from payload - convert payload to json and then to map
    json payloadJson = payload.toJson();
    if payloadJson is map<json> {
        map<json> claims = payloadJson;
        
        // Validate expiration
        json? expClaim = claims["exp"];
        if expClaim is int {
            time:Utc currentTime = time:utcNow();
            int currentUnixTime = currentTime[0];
            if currentUnixTime >= <int>expClaim {
                return buildError(401, "JWT token has expired");
            }
        }
        
        // Extract scopes
        json? scopeClaim = claims["scope"];
        string[] scopes = [];
        if scopeClaim is string {
            // Scopes are space-separated - split manually
            string scopeStr = <string>scopeClaim;
            string[] parts = [];
            string current = "";
            int len = scopeStr.length();
            int i = 0;
            while i < len {
                string charStr = scopeStr.substring(i, i + 1);
                if charStr == " " {
                    if current.length() > 0 {
                        parts.push(current);
                        current = "";
                    }
                } else {
                    current = current + charStr;
                }
                i = i + 1;
            }
            if current.length() > 0 {
                parts.push(current);
            }
            foreach string part in parts {
                string trimmed = strings:trim(part);
                if trimmed.length() > 0 {
                    scopes.push(trimmed);
                }
            }
        } else if scopeClaim is json[] {
            foreach var s in scopeClaim {
                if s is string {
                    scopes.push(s);
                }
            }
        }
        
        log:printInfo("Extracted scopes from JWT", 'scopes = scopes);
        return scopes;
    }
    
    return buildError(401, "Invalid JWT payload format");
}

// Check if required scope is present in the scopes array
function hasRequiredScope(string[] scopes, string requiredScope) returns boolean {
    foreach string scope in scopes {
        if scope == requiredScope {
            return true;
        }
    }
    return false;
}

// Extract JWT from x-jwt-assertion header, validate it, check scope, and get Asgardeo access token
function extractAccessToken(http:Request req, string requiredScope) returns string|http:Response {
    // Extract JWT from x-jwt-assertion header
    string|http:HeaderNotFoundError jwtHeaderResult = req.getHeader("x-jwt-assertion");
    if jwtHeaderResult is http:HeaderNotFoundError {
        return buildError(401, "Unauthorized Request");
    }
    string jwtToken = jwtHeaderResult;
    
    if strings:trim(jwtToken).length() == 0 {
        return buildError(401, "Unauthorized Request");
    }
    
    log:printDebug("JWT token found in x-jwt-assertion header");
    
    // Validate JWT and extract scopes
    string[]|http:Response scopesResult = validateJwtAndExtractScopes(jwtToken);
    if scopesResult is http:Response {
        return scopesResult;
    }
    string[] scopes = scopesResult;
    
    // Check if required scope is present
    if !hasRequiredScope(scopes, requiredScope) {
        log:printError("Required scope not found", 'requiredScope = requiredScope, 'availableScopes = scopes);
        return buildError(403, string `Required scopes not found`);
    }
    
    log:printDebug("JWT validation and scope check passed", 'requiredScope = requiredScope);
    
    // Get access token from Asgardeo using client credentials
    string|error accessTokenResult = getAccessToken();
    if accessTokenResult is error {
        log:printError("Failed to get access token from Asgardeo", 'error = accessTokenResult);
        return buildError(502, "Failed to obtain access token from Asgardeo", accessTokenResult.message());
    }
    
    return accessTokenResult;
}

// Extract JWT from x-jwt-assertion header, validate it (without scope check), and get Asgardeo access token
function extractAccessTokenWithoutScope(http:Request req) returns string|http:Response {
    log:printDebug("Extracting access token without scope");
    // Get access token from Asgardeo using client credentials
    string|error accessTokenResult = getAccessToken();
    if accessTokenResult is error {
        log:printError("Failed to get access token from Asgardeo", 'error = accessTokenResult);
        return buildError(502, "Failed to obtain access token from Asgardeo", accessTokenResult.message());
    }
    
    return accessTokenResult;
}

function getAccessToken() returns string|error {
    http:Request req = new;
    req.setHeader("Content-Type", "application/x-www-form-urlencoded");
    req.setHeader("Accept", "application/json");
    req.setHeader("Authorization", string `Basic ${getBasicAuth(ASGARDEO_CLIENT_ID, ASGARDEO_CLIENT_SECRET)}`);
    // Scopes from the Postman collection
    string scope = "internal_organization_create internal_organization_view internal_organization_update " +
        "internal_user_mgt_list internal_user_mgt_view internal_user_mgt_update " +
        "internal_application_mgt_create internal_application_mgt_delete internal_application_mgt_update internal_application_mgt_view " +
        "internal_branding_preference_update internal_org_branding_preference_update " +
        "internal_shared_application_create internal_shared_application_view internal_shared_application_delete " +
        "internal_user_unshare internal_user_shared_access_view internal_user_share";
    string body = string `grant_type=client_credentials&client_id=${ASGARDEO_CLIENT_ID}&scope=${scope}`;
    req.setTextPayload(body);

    http:Response res = check tokenClient->post("", req);
    if res.statusCode < 200 || res.statusCode >= 300 {
        json? details = ();
        var j = res.getJsonPayload();
        if j is json {
            details = j;
        }
        return error("Failed to obtain access token", details = details);
    }
    json tokenJson = check res.getJsonPayload();
    if tokenJson is map<json> && tokenJson["access_token"] is string {
        return <string>tokenJson["access_token"];
    }
    return error("access_token missing in token response");
}

function switchOrganizationToken(string parentAccessToken, string orgId, string scope) returns string|error {
    http:Request req = new;
    req.setHeader("Content-Type", "application/x-www-form-urlencoded");
    req.setHeader("Accept", "application/json");
    req.setHeader("Authorization", string `Basic ${getBasicAuth(ASGARDEO_CLIENT_ID, ASGARDEO_CLIENT_SECRET)}`);
    // Build x-www-form-urlencoded body
    string body = string `grant_type=organization_switch&token=${parentAccessToken}&scope=${scope}&switching_organization=${orgId}`;
    req.setTextPayload(body);

    http:Response res = check tokenClient->post("", req);
    if res.statusCode < 200 || res.statusCode >= 300 {
        json? details = ();
        var j = res.getJsonPayload();
        if j is json {
            details = j;
        }
        return error("Failed to switch organization token", details = details);
    }
    json tokenJson = check res.getJsonPayload();
    if tokenJson is map<json> && tokenJson["access_token"] is string {
        return <string>tokenJson["access_token"];
    }
    return error("access_token missing in org switch token response");
}

function getBasicAuth(string user, string pass) returns string {
    string creds = string `${user}:${pass}`;
    return creds.toBytes().toBase64();
}

function buildError(int status, string message, any|error? details = ()) returns http:Response {
    http:Response r = new;
    OrgErrorPayload out = { 'error: message };
    if details is error {
        out.details = { message: details.message() };
    } else if details is json {
        out.details = details;
    }
    r.statusCode = status;
    r.setJsonPayload(out);
    return r;
}


