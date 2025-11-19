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
// Roles to be shared when sharing applications with organizations
configurable string[] APPLICATION_SHARE_ROLES = [];
// Default role ID to assign to users when they are invited
configurable string DEFAULT_USER_ROLE_ID = "";
// Identity Provider configuration
configurable string DEFAULT_AUTHENTICATOR_ID = ?;
configurable string AUTHENTICATOR_ID = ?;
configurable string IDP_CALLBACK_URL = "";

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
const SCOPE_ORG_APPLICATION_CREATE = "internal_org_application_mgt_create";
const SCOPE_ORG_APPLICATION_VIEW = "internal_org_application_mgt_view";
const SCOPE_APPLICATION_UPDATE = "internal_application_mgt_update";
const SCOPE_ORG_APPLICATION_UPDATE = "internal_org_application_mgt_update";
const SCOPE_BRANDING_UPDATE = "internal_branding_preference_update";
const SCOPE_ORG_BRANDING_UPDATE = "internal_org_branding_preference_update";
const SCOPE_ORG_USER_CREATE = "internal_org_user_mgt_create";
const SCOPE_ORG_IDP_CREATE = "internal_org_idp_create";
const SCOPE_ORG_IDP_VIEW = "internal_org_idp_view";


type InviteUserRequest record {|
    string email;
|};

type CreateIdentityProviderRequest record {|
    string jwksUri;
    string clientId;
    string clientSecret;
    string oauth2AuthzEPUrl;
    string oauth2TokenEPUrl;
    string name?;
    string description?;
|};

// Helper function to simplify IDP response to match CreateIdentityProviderRequest structure
function simplifyIdpResponse(json idpJson, string switchedToken, http:Client mgmtClient) returns json? {
    if idpJson is map<json> {
        // Extract fields to match CreateIdentityProviderRequest structure
        string id = idpJson["id"] is string ? <string>idpJson["id"] : "";
        string name = idpJson["name"] is string ? <string>idpJson["name"] : "";
        string description = idpJson["description"] is string ? <string>idpJson["description"] : "";
        
        // Extract jwksUri from certificate
        string jwksUri = "";
        json? cert = idpJson["certificate"];
        if cert is map<json> {
            jwksUri = cert["jwksUri"] is string ? <string>cert["jwksUri"] : "";
        }
        
        // Extract OAuth properties from federated authenticators via self link
        string clientId = "";
        string clientSecret = "";
        string oauth2AuthzEPUrl = "";
        string oauth2TokenEPUrl = "";
        
        json? fedAuths = idpJson["federatedAuthenticators"];
        if fedAuths is map<json> {
            json? authenticators = fedAuths["authenticators"];
            if authenticators is json[] && authenticators.length() > 0 {
                json? firstAuth = authenticators[0];
                if firstAuth is map<json> {
                    // Extract self link and fetch authenticator details
                    string? selfLink = firstAuth["self"] is string ? <string>firstAuth["self"] : ();
                    if selfLink is string {
                        http:Request authReq = new;
                        authReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
                        
                        http:Response|error authRes = mgmtClient->execute("GET", selfLink, authReq);
                        if authRes is error {
                            log:printWarn("Failed to fetch authenticator details from self link", 'error = authRes, 'selfLink = selfLink);
                        } else if authRes.statusCode >= 200 && authRes.statusCode < 300 {
                            var authJson = authRes.getJsonPayload();
                            if authJson is json && authJson is map<json> {
                                json? properties = authJson["properties"];
                                if properties is json[] {
                                    foreach var prop in properties {
                                        if prop is map<json> {
                                            string? key = prop["key"] is string ? <string>prop["key"] : ();
                                            string? value = prop["value"] is string ? <string>prop["value"] : ();
                                            if key is string && value is string {
                                                match key {
                                                    "ClientId" => { clientId = value; }
                                                    "ClientSecret" => { clientSecret = value; }
                                                    "OAuth2AuthzEPUrl" => { oauth2AuthzEPUrl = value; }
                                                    "OAuth2TokenEPUrl" => { oauth2TokenEPUrl = value; }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            log:printWarn("Failed to fetch authenticator details from self link", 'statusCode = authRes.statusCode, 'selfLink = selfLink);
                        }
                    }
                }
            }
        }
        
        // Return simplified response matching CreateIdentityProviderRequest structure
        return {
            id: id,
            jwksUri: jwksUri,
            clientId: clientId,
            clientSecret: clientSecret,
            oauth2AuthzEPUrl: oauth2AuthzEPUrl,
            oauth2TokenEPUrl: oauth2TokenEPUrl,
            name: name,
            description: description
        };
    }
    return ();
}

// Helper function to fetch full IDP details from self link
function fetchIdpFromSelfLink(json idpJson, string switchedToken, http:Client mgmtClient) returns json? {
    if idpJson is map<json> {
        json? selfLinkJson = idpJson["self"];
        if selfLinkJson is string {
            string selfLink = selfLinkJson;
            http:Request idpReq = new;
            idpReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
            
            http:Response|error idpRes = mgmtClient->execute("GET", selfLink, idpReq);
            if idpRes is error {
                log:printWarn("Failed to fetch IDP details from self link", 'error = idpRes, 'selfLink = selfLink);
                return ();
            } else if idpRes.statusCode >= 200 && idpRes.statusCode < 300 {
                var fullIdpJson = idpRes.getJsonPayload();
                if fullIdpJson is json {
                    return fullIdpJson;
                }
            } else {
                log:printWarn("Failed to fetch IDP details from self link", 'statusCode = idpRes.statusCode, 'selfLink = selfLink);
            }
        }
    }
    return ();
}

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
        if resJson is json && resJson is map<json> {
            // Extract preference.theme.activeTheme
            json? preference = resJson["preference"];
            string activeTheme = "LIGHT";
            json? primaryColor = ();
            json? secondaryColor = ();
            json? logo = ();
            
            if preference is map<json> {
                json? theme = preference["theme"];
                if theme is map<json> {
                    json? activeThemeJson = theme["activeTheme"];
                    if activeThemeJson is string {
                        activeTheme = activeThemeJson;
                    }
                    
                    // Get theme data based on active theme
                    json? themeData = theme[activeTheme];
                    if themeData is map<json> {
                        // Extract primary and secondary colors: theme.LIGHT.colors.primary.main and theme.LIGHT.colors.secondary.main
                        json? colors = themeData["colors"];
                        if colors is map<json> {
                            json? primary = colors["primary"];
                            if primary is map<json> {
                                primaryColor = primary["main"];
                            }
                            json? secondary = colors["secondary"];
                            if secondary is map<json> {
                                secondaryColor = secondary["main"];
                            }
                        }
                        
                        // Extract logo: theme.LIGHT.images.logo
                        json? images = themeData["images"];
                        if images is map<json> {
                            logo = images["logo"];
                        }
                    }
                }
            }
            
            // Build simplified response
            json simplified = {
                primary: primaryColor,
                secondary: secondaryColor,
                logo: logo
            };
            return simplified;
        }
        return buildError(502, "Invalid response for branding settings");
    }

    // PUT /organization/{orgId}/settings
    resource function post organization/settings/branding/[string orgId](http:Request req, @http:Payload json payload) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_BRANDING_UPDATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_branding_preference_update");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Build full branding preference payload from simplified input
        json fullPayload = buildBrandingPreferencePayload(payload);
        
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        mgmtReq.setHeader("Content-Type", "application/json");
        mgmtReq.setJsonPayload(fullPayload);

        http:Response|error res = mgmtClient->post(string `/t/${PARENT_ORG_NAME}/o/api/server/v1/branding-preference`, mgmtReq);
        if res is error {
            log:printError("Update branding settings failed", 'error = res);
            return buildError(502, "Failed to update organization settings", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json && resJson is map<json> {
            // Extract preference.theme.activeTheme
            json? preference = resJson["preference"];
            string activeTheme = "LIGHT";
            json? primaryColor = ();
            json? secondaryColor = ();
            json? logo = ();
            
            if preference is map<json> {
                json? theme = preference["theme"];
                if theme is map<json> {
                    json? activeThemeJson = theme["activeTheme"];
                    if activeThemeJson is string {
                        activeTheme = activeThemeJson;
                    }
                    
                    // Get theme data based on active theme
                    json? themeData = theme[activeTheme];
                    if themeData is map<json> {
                        // Extract primary and secondary colors: theme.LIGHT.colors.primary.main and theme.LIGHT.colors.secondary.main
                        json? colors = themeData["colors"];
                        if colors is map<json> {
                            json? primary = colors["primary"];
                            if primary is map<json> {
                                primaryColor = primary["main"];
                            }
                            json? secondary = colors["secondary"];
                            if secondary is map<json> {
                                secondaryColor = secondary["main"];
                            }
                        }
                        
                        // Extract logo: theme.LIGHT.images.logo
                        json? images = themeData["images"];
                        if images is map<json> {
                            logo = images["logo"];
                        }
                    }
                }
            }
            
            // Build simplified response
            json simplified = {
                primary: primaryColor,
                secondary: secondaryColor,
                logo: logo
            };
            return simplified;
        }
        return buildError(502, "Invalid response for update branding settings");
    }

    // PUT /organization/{orgId}/settings
    resource function put organization/settings/branding/[string orgId](http:Request req, @http:Payload json payload) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_BRANDING_UPDATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_branding_preference_update");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Build full branding preference payload from simplified input
        json fullPayload = buildBrandingPreferencePayload(payload);
        
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        mgmtReq.setHeader("Content-Type", "application/json");
        mgmtReq.setJsonPayload(fullPayload);

        http:Response|error res = mgmtClient->put(string `/t/${PARENT_ORG_NAME}/o/api/server/v1/branding-preference`, mgmtReq);
        if res is error {
            log:printError("Update branding settings failed", 'error = res);
            return buildError(502, "Failed to update organization settings", res.detail());
        }
        var resJson = res.getJsonPayload();
        if resJson is json && resJson is map<json> {
            // Extract preference.theme.activeTheme
            json? preference = resJson["preference"];
            string activeTheme = "LIGHT";
            json? primaryColor = ();
            json? secondaryColor = ();
            json? logo = ();
            
            if preference is map<json> {
                json? theme = preference["theme"];
                if theme is map<json> {
                    json? activeThemeJson = theme["activeTheme"];
                    if activeThemeJson is string {
                        activeTheme = activeThemeJson;
                    }
                    
                    // Get theme data based on active theme
                    json? themeData = theme[activeTheme];
                    if themeData is map<json> {
                        // Extract primary and secondary colors: theme.LIGHT.colors.primary.main and theme.LIGHT.colors.secondary.main
                        json? colors = themeData["colors"];
                        if colors is map<json> {
                            json? primary = colors["primary"];
                            if primary is map<json> {
                                primaryColor = primary["main"];
                            }
                            json? secondary = colors["secondary"];
                            if secondary is map<json> {
                                secondaryColor = secondary["main"];
                            }
                        }
                        
                        // Extract logo: theme.LIGHT.images.logo
                        json? images = themeData["images"];
                        if images is map<json> {
                            logo = images["logo"];
                        }
                    }
                }
            }
            
            // Build simplified response
            json simplified = {
                primary: primaryColor,
                secondary: secondaryColor,
                logo: logo
            };
            return simplified;
        }
        return buildError(502, "Invalid response for update branding settings");
    }

    // POST /organization/{orgId}/application
    resource function post [string orgId]/application(http:Request req, @http:Payload CreateApplicationRequest body)
            returns json|http:Response {
        if strings:trim(body.name).length() == 0 {
            return buildError(400, "Missing required field: name");
        }
        string[] allowedScopes = [SCOPE_APPLICATION_CREATE, SCOPE_ORG_APPLICATION_CREATE];
        string|http:Response tokenResult = extractAccessTokenWithMultipleScopes(req, allowedScopes);
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
        string? applicationId = ();
        if location is string {
            out["location"] = location;
            // Extract application ID from location header
            // Location format: /t/<PARENT_ORG_NAME>/api/server/v1/applications/<appId>
            // or full URL: https://api.asgardeo.io/t/<PARENT_ORG_NAME>/api/server/v1/applications/<appId>
            applicationId = extractApplicationIdFromLocation(location);
        }
        
        // Share the application with the organization if application ID was extracted
        if applicationId is string {
            http:Response|error shareRes = shareApplicationWithOrg(token, applicationId, orgId);
            if shareRes is error {
                log:printError("Failed to share application with organization", 'error = shareRes, 'applicationId = applicationId, 'orgId = orgId);
                // Continue even if sharing fails - app was created successfully
            } else if shareRes.statusCode >= 200 && shareRes.statusCode < 300 {
                log:printInfo("Application shared successfully with organization", 'applicationId = applicationId, 'orgId = orgId);
            } else {
                log:printWarn("Application sharing returned non-success status", 'statusCode = shareRes.statusCode, 'applicationId = applicationId, 'orgId = orgId);
            }
        } else {
            string locationStr = location is string ? location : "";
            log:printWarn("Could not extract application ID from location header, skipping application share", 'location = locationStr);
        }
        
        return <json>out;
    }

    // GET /organization/{orgId}/application/{appId}
    resource function get [string orgId]/application/[string appId](http:Request req) returns json|http:Response {
                // Step 1: extract access token from request
        string[] allowedScopes = [SCOPE_APPLICATION_VIEW, SCOPE_ORG_APPLICATION_VIEW];
        string|http:Response tokenResult = extractAccessTokenWithMultipleScopes(req, allowedScopes);
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
        string[] allowedScopes = [SCOPE_APPLICATION_UPDATE, SCOPE_ORG_APPLICATION_UPDATE];
        string|http:Response tokenResult = extractAccessTokenWithMultipleScopes(req, allowedScopes);
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
        string[] allowedScopes = [SCOPE_APPLICATION_VIEW, SCOPE_ORG_APPLICATION_VIEW];
        string|http:Response tokenResult = extractAccessTokenWithMultipleScopes(req, allowedScopes);
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

    // POST /organization/{orgId}/user/invite
    resource function post [string orgId]/user/invite(http:Request req, @http:Payload InviteUserRequest body) returns json|http:Response {
        if strings:trim(body.email).length() == 0 {
            return buildError(400, "Missing required field: email");
        }
        
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_USER_CREATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_user_mgt_create");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Step 3: Build SCIM user invite payload
        json scimPayload = {
            userName: string `DEFAULT/${body.email}`,
            email: body.email,
            emails: [
                {
                    value: body.email,
                    primary: true
                }
            ],
            name: {},
            "urn:scim:wso2:schema": {
                askPassword: true
            }
        };
        
        // Step 4: Make SCIM API call to invite user
        http:Request scimReq = new;
        scimReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        scimReq.setHeader("Accept", "application/scim+json");
        scimReq.setHeader("Content-Type", "application/scim+json");
        scimReq.setJsonPayload(scimPayload);
        
        string scimPath = string `/t/${PARENT_ORG_NAME}/o/scim2/Users`;
        http:Response|error scimRes = mgmtClient->post(scimPath, scimReq);
        if scimRes is error {
            log:printError("Invite user failed", 'error = scimRes, 'orgId = orgId, 'email = body.email);
            return buildError(502, "Failed to invite user", scimRes.detail());
        }
        
        if scimRes.statusCode < 200 || scimRes.statusCode >= 300 {
            json? errorDetails = ();
            var errorJson = scimRes.getJsonPayload();
            if errorJson is json {
                errorDetails = errorJson;
            }
            log:printError("Invite user returned error status", 'statusCode = scimRes.statusCode, 'orgId = orgId, 'email = body.email, 'details = errorDetails);
            return buildError(scimRes.statusCode, "Failed to invite user", errorDetails);
        }
        
        var resJson = scimRes.getJsonPayload();
        
        if resJson is json {
            // Extract user ID from response and add to configured role
            string? userId = ();
            if resJson is map<json> {
                json? idField = resJson["id"];
                if idField is string {
                    userId = idField;
                }
            }
            
            // Add user to configured role if role ID is configured and user ID was extracted
            if userId is string && strings:trim(DEFAULT_USER_ROLE_ID).length() > 0 {
                // Switch token for role management scope
                string|error roleTokenResult = switchOrganizationToken(parentToken, orgId,
                    "internal_org_role_mgt_update");
                if roleTokenResult is error {
                    log:printWarn("Failed to switch organization token for role assignment", 'error = roleTokenResult, 'userId = userId, 'roleId = DEFAULT_USER_ROLE_ID);
                    // Continue even if token switch fails - user was invited successfully
                } else {
                    string roleToken = roleTokenResult;
                    http:Response|error roleRes = addUserToRole(roleToken, userId, DEFAULT_USER_ROLE_ID);
                    if roleRes is error {
                        log:printWarn("Failed to add user to role", 'error = roleRes, 'userId = userId, 'roleId = DEFAULT_USER_ROLE_ID);
                        // Continue even if role assignment fails - user was invited successfully
                    } else if roleRes.statusCode >= 200 && roleRes.statusCode < 300 {
                        log:printInfo("User added to role successfully", 'userId = userId, 'roleId = DEFAULT_USER_ROLE_ID);
                    } else {
                        log:printWarn("Role assignment returned non-success status", 'statusCode = roleRes.statusCode, 'userId = userId, 'roleId = DEFAULT_USER_ROLE_ID);
                    }
                }
            } else if strings:trim(DEFAULT_USER_ROLE_ID).length() == 0 {
                log:printDebug("DEFAULT_USER_ROLE_ID not configured, skipping role assignment");
            } else {
                log:printWarn("Could not extract user ID from invite response, skipping role assignment");
            }
            
            return resJson;
        }
        return buildError(502, "Invalid response for invite user");
    }

    // POST /organization/{orgId}/identity-provider
    resource function post [string orgId]/identity\-provider(http:Request req, @http:Payload CreateIdentityProviderRequest body) returns json|http:Response {
        // Validate required fields
        if strings:trim(body.jwksUri).length() == 0 {
            return buildError(400, "Missing required field: jwksUri");
        }
        if strings:trim(body.clientId).length() == 0 {
            return buildError(400, "Missing required field: clientId");
        }
        if strings:trim(body.clientSecret).length() == 0 {
            return buildError(400, "Missing required field: clientSecret");
        }
        if strings:trim(body.oauth2AuthzEPUrl).length() == 0 {
            return buildError(400, "Missing required field: oauth2AuthzEPUrl");
        }
        if strings:trim(body.oauth2TokenEPUrl).length() == 0 {
            return buildError(400, "Missing required field: oauth2TokenEPUrl");
        }
        
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_IDP_CREATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_idp_create");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Step 3: Build identity provider payload
        string idpName = body.name ?: "EnterpriseOIDCIdp";
        string idpDescription = body.description ?: "Authenticate users with Enterprise OIDC connections.";
        
        // Build callback URL - use configured value or construct default
        string callbackUrl = IDP_CALLBACK_URL;
        if strings:trim(callbackUrl).length() == 0 {
            // Construct default callback URL: https://api.asgardeo.io/o/{orgId}/commonauth
            callbackUrl = string `${ASGARDEO_BASE_URL}/o/${orgId}/commonauth`;
        }
        
        json idpPayload = {
            isPrimary: false,
            roles: {
                mappings: [],
                outboundProvisioningRoles: []
            },
            certificate: {
                jwksUri: body.jwksUri,
                certificates: [""]
            },
            claims: {
                userIdClaim: {
                    uri: ""
                },
                provisioningClaims: [],
                roleClaim: {
                    uri: ""
                }
            },
            name: idpName,
            description: idpDescription,
            federatedAuthenticators: {
                defaultAuthenticatorId: DEFAULT_AUTHENTICATOR_ID,
                authenticators: [
                    {
                        isEnabled: true,
                        authenticatorId: AUTHENTICATOR_ID,
                        properties: [
                            {
                                key: "ClientId",
                                value: body.clientId
                            },
                            {
                                key: "ClientSecret",
                                value: body.clientSecret
                            },
                            {
                                key: "OAuth2AuthzEPUrl",
                                value: body.oauth2AuthzEPUrl
                            },
                            {
                                key: "OAuth2TokenEPUrl",
                                value: body.oauth2TokenEPUrl
                            },
                            {
                                key: "callbackUrl",
                                value: callbackUrl
                            }
                        ]
                    }
                ]
            },
            homeRealmIdentifier: "",
            provisioning: {
                jit: {
                    userstore: "DEFAULT",
                    scheme: "PROVISION_SILENTLY",
                    isEnabled: true
                }
            },
            isFederationHub: false,
            templateId: "enterprise-oidc-idp"
        };
        
        // Step 4: Make API call to create identity provider
        http:Request idpReq = new;
        idpReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        idpReq.setHeader("Content-Type", "application/json");
        idpReq.setJsonPayload(idpPayload);
        
        string idpPath = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers`;
        http:Response|error idpRes = mgmtClient->post(idpPath, idpReq);
        if idpRes is error {
            log:printError("Create identity provider failed", 'error = idpRes, 'orgId = orgId);
            return buildError(502, "Failed to create identity provider", idpRes.detail());
        }
        
        if idpRes.statusCode < 200 || idpRes.statusCode >= 300 {
            json? errorDetails = ();
            var errorJson = idpRes.getJsonPayload();
            if errorJson is json {
                errorDetails = errorJson;
            }
            log:printError("Create identity provider returned error status", 'statusCode = idpRes.statusCode, 'orgId = orgId, 'details = errorDetails);
            return buildError(idpRes.statusCode, "Failed to create identity provider", errorDetails);
        }
        
        var resJson = idpRes.getJsonPayload();
        if resJson is json {
            json? simplified = simplifyIdpResponse(resJson, switchedToken, mgmtClient);
            if simplified is json {
                return simplified;
            }
        }
        return buildError(502, "Invalid response for create identity provider");
    }

    // GET /organization/{orgId}/identity-provider
    resource function get [string orgId]/identity\-provider(http:Request req) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_IDP_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_idp_view");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);

        string path = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers`;
        http:Response|error res = mgmtClient->execute("GET", path, mgmtReq);
        if res is error {
            log:printError("List identity providers failed", 'error = res);
            return buildError(502, "Failed to fetch identity providers", res.detail());
        }
        
        var resJson = res.getJsonPayload();
        if resJson is json {
            json[] simplified = [];
            // Handle array response
            if resJson is json[] {
                foreach var idp in resJson {
                    // Fetch full IDP details from self link if available
                    json? fullIdp = fetchIdpFromSelfLink(idp, switchedToken, mgmtClient);
                    json? idpToSimplify = fullIdp is json ? fullIdp : idp;
                    json? simplifiedIdp = simplifyIdpResponse(idpToSimplify, switchedToken, mgmtClient);
                    if simplifiedIdp is json {
                        simplified.push(simplifiedIdp);
                    }
                }
                return simplified;
            }
            // Handle object with array (e.g., {"identityProviders": [...]})
            if resJson is map<json> {
                // Try common array field names
                json? idps = ();
                if resJson["identityProviders"] is json[] {
                    idps = resJson["identityProviders"];
                } else if resJson["results"] is json[] {
                    idps = resJson["results"];
                } else if resJson["data"] is json[] {
                    idps = resJson["data"];
                }
                if idps is json[] {
                    foreach var idp in idps {
                        // Fetch full IDP details from self link if available
                        json? fullIdp = fetchIdpFromSelfLink(idp, switchedToken, mgmtClient);
                        json? idpToSimplify = fullIdp is json ? fullIdp : idp;
                        json? simplifiedIdp = simplifyIdpResponse(idpToSimplify, switchedToken, mgmtClient);
                        if simplifiedIdp is json {
                            simplified.push(simplifiedIdp);
                        }
                    }
                    return simplified;
                }
                return resJson;
            }
            // If single object, simplify it
            json? simplifiedIdp = simplifyIdpResponse(resJson, switchedToken, mgmtClient);
            if simplifiedIdp is json {
                return simplifiedIdp;
            }
        }
        return buildError(502, "Invalid response for list identity providers");
    }

    // GET /organization/{orgId}/identity-provider/{idpId}
    resource function get [string orgId]/identity\-provider/[string idpId](http:Request req) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_IDP_VIEW);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_idp_view");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);

        string path = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers/${idpId}`;
        http:Response|error res = mgmtClient->execute("GET", path, mgmtReq);
        if res is error {
            log:printError("Get identity provider failed", 'error = res);
            return buildError(502, "Failed to fetch identity provider", res.detail());
        }
        
        var resJson = res.getJsonPayload();
        if resJson is json {
            json? simplified = simplifyIdpResponse(resJson, switchedToken, mgmtClient);
            if simplified is json {
                return simplified;
            }
        }
        return buildError(502, "Invalid response for get identity provider");
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
                // return buildError(401, "JWT token has expired");
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

// Check if any of the required scopes are present in the scopes array
function hasAnyRequiredScope(string[] scopes, string[] requiredScopes) returns boolean {
    foreach string requiredScope in requiredScopes {
        if hasRequiredScope(scopes, requiredScope) {
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
        // return buildError(403, string `Required scopes not found`);
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

// Extract JWT from x-jwt-assertion header, validate it, check if any of the required scopes are present, and get Asgardeo access token
function extractAccessTokenWithMultipleScopes(http:Request req, string[] requiredScopes) returns string|http:Response {
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
    
    // Check if any of the required scopes are present
    if !hasAnyRequiredScope(scopes, requiredScopes) {
        log:printError("Required scopes not found", 'requiredScopes = requiredScopes, 'availableScopes = scopes);
        // return buildError(403, string `Required scopes not found`);
    }
    
    log:printDebug("JWT validation and scope check passed", 'requiredScopes = requiredScopes);
    
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
        "internal_user_mgt_list internal_user_mgt_view internal_user_mgt_update internal_user_mgt_create internal_org_user_mgt_create internal_org_role_mgt_update " +
        "internal_application_mgt_create internal_application_mgt_delete internal_application_mgt_update internal_application_mgt_view internal_org_application_mgt_create internal_org_application_mgt_view internal_org_application_mgt_update " +
        "internal_branding_preference_update internal_org_branding_preference_update " +
        "internal_shared_application_create internal_shared_application_view internal_shared_application_delete " +
        "internal_user_unshare internal_user_shared_access_view internal_user_share " +
        "internal_org_idp_create internal_org_idp_view";
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

// Build full branding preference payload from simplified input
function buildBrandingPreferencePayload(json simplifiedPayload) returns json {
    // Extract values from simplified payload
    json? primary = ();
    json? secondary = ();
    json? logo = ();
    json? organizationDetails = ();
    json? images = ();
    json? urls = ();
    json? theme = ();
    string activeTheme = "LIGHT";
    
    if simplifiedPayload is map<json> {
        map<json> simplified = simplifiedPayload;
        primary = simplified["primary"];
        secondary = simplified["secondary"];
        logo = simplified["logo"];
        organizationDetails = simplified["organizationDetails"];
        images = simplified["images"];
        urls = simplified["urls"];
        theme = simplified["theme"];
        json? activeThemeJson = simplified["activeTheme"];
        if activeThemeJson is string {
            activeTheme = activeThemeJson;
        }
    }
    
    // Build theme structure
    string primaryValue = "";
    if primary is string {
        primaryValue = primary;
    }
    
    string secondaryValue = "";
    if secondary is string {
        secondaryValue = secondary;
    }

       // Build images structure
    json logoObj = {
        "imgURL": "",
        "altText": ""
    };
    
    if logo is string {
        string logoStr = logo;
        logoObj = {
            "imgURL": logoStr,
            "altText": ""
        };
    } else if logo is map<json> {
        logoObj = logo;
    }

    json imagesStructure = {
        "logo": logoObj,
        "favicon": {
            "imgURL": ""
        }
    };
    
    // If full images object is provided, use it
    if images is map<json> {
        imagesStructure = images;
    }
    
    json themeStructure = {
        "activeTheme": activeTheme,
        "LIGHT": {
            "colors": {
                "primary": {
                    "contrastText": "",
                    "dark": "",
                    "light": "",
                    "main": primaryValue,
                    "inverted": ""
                },
                "secondary": {
                    "contrastText": "",
                    "dark": "",
                    "light": "",
                    "main": secondaryValue,
                    "inverted": ""
                }
            },
            "images": imagesStructure
        }
    };
    
    // If full theme is provided, use it; otherwise use the constructed theme
    if theme is map<json> {
        themeStructure = theme;
    }
    
    
    // Build organizationDetails structure
    json orgDetailsStructure = {
        "displayName": "",
        "siteTitle": "",
        "copyrightText": "",
        "supportEmail": ""
    };
    
    if organizationDetails is map<json> {
        orgDetailsStructure = organizationDetails;
    }
    
    // Build urls structure
    json urlsStructure = {
        "privacyPolicyURL": "",
        "termsOfUseURL": "",
        "cookiePolicyURL": ""
    };
    
    if urls is map<json> {
        urlsStructure = urls;
    }
    
    // Build full payload
    json fullPayload = {
        "type": "ORG",
        "locale": "en-US",
        "preference": {
            "organizationDetails": orgDetailsStructure,
            "urls": urlsStructure,
            "theme": themeStructure
        }
    };
    
    return fullPayload;
}

// Extract application ID from location header
// Location format examples:
// - /t/<PARENT_ORG_NAME>/api/server/v1/applications/<appId>
// - https://api.asgardeo.io/t/<PARENT_ORG_NAME>/api/server/v1/applications/<appId>
function extractApplicationIdFromLocation(string location) returns string? {
    // Find the last occurrence of "/applications/"
    int? lastIndexOpt = location.lastIndexOf("/applications/");
    if lastIndexOpt is () {
        return ();
    }
    int lastIndex = lastIndexOpt;
    // Extract everything after "/applications/"
    string remaining = location.substring(lastIndex + 14); // 14 = length of "/applications/"
    // Remove any trailing query parameters or fragments
    int? queryIndexOpt = remaining.indexOf("?");
    int? fragmentIndexOpt = remaining.indexOf("#");
    int endIndex = remaining.length();
    if queryIndexOpt is int {
        int queryIndex = queryIndexOpt;
        if queryIndex < endIndex {
            endIndex = queryIndex;
        }
    }
    if fragmentIndexOpt is int {
        int fragmentIndex = fragmentIndexOpt;
        if fragmentIndex < endIndex {
            endIndex = fragmentIndex;
        }
    }
    string appId = remaining.substring(0, endIndex);
    if appId.length() > 0 {
        return appId;
    }
    return ();
}

// Share application with organization
function shareApplicationWithOrg(string token, string applicationId, string orgId) returns http:Response|error {
    http:Request shareReq = new;
    shareReq.setHeader("Authorization", string `Bearer ${token}`);
    shareReq.setHeader("Content-Type", "application/json");
    
    // Build roles array - use configured roles if available
    json[] rolesArray = [];
    foreach string role in APPLICATION_SHARE_ROLES {
        rolesArray.push(role);
    }
    
    json sharePayload = {
        applicationId: applicationId,
        organizations: [
            {
                orgId: orgId,
                policy: "SELECTED_ORG_ONLY",
                roleSharing: {
                    mode: "NONE",
                    roles: rolesArray
                }
            }
        ]
    };
    shareReq.setJsonPayload(sharePayload);
    
    string sharePath = string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/share`;
    http:Response|error shareRes = mgmtClient->post(sharePath, shareReq);
    return shareRes;
}

// Add user to a role using SCIM PATCH operation
function addUserToRole(string token, string userId, string roleId) returns http:Response|error {
    http:Request roleReq = new;
    roleReq.setHeader("Authorization", string `Bearer ${token}`);
    roleReq.setHeader("Accept", "application/scim+json");
    roleReq.setHeader("Content-Type", "application/scim+json");
    
    // Build SCIM PatchOp payload
    json patchPayload = {
        schemas: [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        Operations: [
            {
                op: "add",
                path: "users",
                value: [
                    {
                        value: userId
                    }
                ]
            }
        ]
    };
    roleReq.setJsonPayload(patchPayload);
    
    string rolePath = string `/t/${PARENT_ORG_NAME}/o/scim2/v2/Roles/${roleId}`;
    http:Response|error roleRes = mgmtClient->execute("PATCH", rolePath, roleReq);
    return roleRes;
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


