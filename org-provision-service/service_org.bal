import ballerina/http;
import ballerina/log;
import ballerina/lang.'string as strings;

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

service /organization on provServiceListener {

    // GET /organization
    resource function get .() returns json|http:Response {
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        // List direct children for configured parent
        // Asgardeo: GET /api/server/v1/organizations?parentId=<PARENT_ORG_ID>
        string path = string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations?parentId=${PARENT_ORG_ID}`;

        http:Response|error res = mgmtClient->execute("GET", path, req);
        if res is error {
            log:printError("List organizations failed", 'error = res);
            return buildError(502, "Failed to fetch organizations", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for organizations list");
    }

    // POST /organization
    resource function post .(@http:Payload CreateOrganizationRequest body) returns json|http:Response {
        if strings:trim(body.name).length() == 0 {
            return buildError(400, "Missing required field: name");
        }
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        req.setHeader("Content-Type", "application/json");
        json payload = {
            name: body.name,
            description: body.description,
            parentId: PARENT_ORG_ID,
            "type": "TENANT"
        };
        req.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations`, req);
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
    resource function get [string orgId]() returns json|http:Response {
        
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        req.setHeader(ORG_SCOPE_HEADER, orgId);

        // Get applications
        http:Response|error appsRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/api/server/v1/applications`, req);
        if appsRes is error {
            log:printError("List applications failed", 'error = appsRes);
            return buildError(502, "Failed to fetch applications", appsRes.detail());
        }
        json apps = {};
        var appsJ = appsRes.getJsonPayload();
        if appsJ is json {
            apps = appsJ;
        }

        // Get organization details
        http:Response|error orgRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations/${orgId}`, req);
        json orgInfo = {};
        if orgRes is http:Response {
            var orgJ = orgRes.getJsonPayload();
            if orgJ is json {
                orgInfo = orgJ;
            }
        }

        return { organization: orgInfo, applications: apps };
    }

    // GET /organization/{orgId}/settings
    resource function get settings/[string orgId]() returns json|http:Response {
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);

        // Branding settings endpoint can vary; try a common path
        http:Response|error res = mgmtClient->execute("GET", string `/o/${orgId}/api/server/v1/branding-preference?locale=en-US&name=${orgId}&type=ORG`, req);
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

    // PUT /organization/{orgId}/settings
    resource function post settings/[string orgId](@http:Payload json payload) returns json|http:Response {
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        req.setHeader("Content-Type", "application/json");
        req.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/o/${orgId}/api/server/v1/branding-preference`, req);
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
    resource function post application/[string orgId](@http:Payload CreateApplicationRequest body)
            returns json|http:Response {
        if strings:trim(body.name).length() == 0 {
            return buildError(400, "Missing required field: name");
        }
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        req.setHeader("Content-Type", "application/json");

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
        req.setJsonPayload(payload);

        http:Response|error res = mgmtClient->post(string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/`, req);
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
    resource function get [string orgId]/application/[string appId]() returns json|http:Response {
                // Step 1: obtain parent access token with broad scopes
        string parentToken = checkpanic getAccessToken();
        // Step 2: exchange token for target organization using organization_switch grant
        string switchedToken = checkpanic switchOrganizationToken(parentToken, orgId,
            "internal_org_application_mgt_view");
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${switchedToken}`);

        http:Response|error res = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications/${appId}`, req);
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
        http:Response|error credsRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/${appId}/inbound-protocols/oidc/metadata`, req);
        json creds = {};
        if credsRes is http:Response {
            var credsJ = credsRes.getJsonPayload();
            if credsJ is json {
                creds = credsJ;
            }
        }
        return { application: app, credentials: creds };
    }

    // PUT /organization/{orgId}/application/{appId}
    resource function put [string orgId]/application/[string appId](@http:Payload CreateApplicationRequest body)
            returns json|http:Response {
        string token = checkpanic getAccessToken();
        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${token}`);
        req.setHeader(ORG_SCOPE_HEADER, orgId);
        req.setHeader("Content-Type", "application/json");

        json patch = {
            inboundProtocolConfiguration: {
                oidc: {
                    grantTypes: body.grantTypes ?: [],
                    callbackURLs: body.callbackURLs ?: []
                }
            }
        };
        req.setJsonPayload(patch);

        http:Response|error res = mgmtClient->put(string `/api/server/v1/applications/${appId}`, req);
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
    resource function get [string orgId]/application(string? filter, int? limitCount, int? offsetCount)
            returns json|http:Response {
        // Step 1: obtain parent access token with broad scopes
        string parentToken = checkpanic getAccessToken();
        // Step 2: exchange token for target organization using organization_switch grant
        string switchedToken = checkpanic switchOrganizationToken(parentToken, orgId,
            "internal_org_application_mgt_view");

        http:Request req = new;
        req.setHeader("Authorization", string `Bearer ${switchedToken}`);

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
        http:Response|error res = mgmtClient->execute("GET", path, req);
        if res is error {
            log:printError("Search applications failed", 'error = res);
            return buildError(502, "Failed to search applications", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json {
            return resJson;
        }
        return buildError(502, "Invalid response for search applications");
    }
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


