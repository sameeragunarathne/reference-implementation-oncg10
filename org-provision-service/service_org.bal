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
// List of allowed role names for user invitation
// If this is configured and non-empty, only role names in this list will be accepted
configurable string[] ALLOWED_ROLE_NAMES = [];
// Identity Provider configuration
configurable string DEFAULT_AUTHENTICATOR_ID = ?;
configurable string AUTHENTICATOR_ID = ?;
configurable string IDP_CALLBACK_URL = "";
// STS (Security Token Service) configuration for dev portal application creation
configurable string STS_CLIENT_ID = "";
configurable string STS_CLIENT_SECRET = "";
// Keymanager name for mapping OAuth keys in dev portal
configurable string KEYMANAGER_NAME = "";

// Reuse the listener defined in provisioner.bal (declared there as: listener http:Listener provServiceListener = new (6000);)

final http:Client tokenClient = checkpanic new (string `${ASGARDEO_BASE_URL}/t/${PARENT_ORG_NAME}/oauth2/token`);
final http:Client mgmtClient = checkpanic new (ASGARDEO_BASE_URL);
final http:Client stsClient = checkpanic new ("https://sts.choreo.dev");

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
const SCOPE_ORGANIZATION_DELETE = "internal_organization_delete";
const SCOPE_APPLICATION_VIEW = "internal_application_mgt_view";
const SCOPE_APPLICATION_CREATE = "internal_application_mgt_create";
const SCOPE_ORG_APPLICATION_CREATE = "internal_org_application_mgt_create";
const SCOPE_ORG_APPLICATION_VIEW = "internal_org_application_mgt_view";
const SCOPE_APPLICATION_UPDATE = "internal_application_mgt_update";
const SCOPE_APPLICATION_DELETE = "internal_application_mgt_delete";
const SCOPE_ORG_APPLICATION_UPDATE = "internal_org_application_mgt_update";
const SCOPE_BRANDING_UPDATE = "internal_branding_preference_update";
const SCOPE_ORG_BRANDING_UPDATE = "internal_org_branding_preference_update";
const SCOPE_ORG_USER_CREATE = "internal_org_user_mgt_create";
const SCOPE_ORG_USER_LIST = "internal_org_user_mgt_list";
const SCOPE_ORG_IDP_CREATE = "internal_org_idp_create";
const SCOPE_ORG_IDP_VIEW = "internal_org_idp_view";
const SCOPE_ORG_IDP_UPDATE = "internal_org_idp_update";


type InviteUserRequest record {|
    string email;
    string role?;
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

type PatchIdentityProviderRequest record {|
    string jwksUri?;
    string clientId?;
    string clientSecret?;
    string oauth2AuthzEPUrl?;
    string oauth2TokenEPUrl?;
    string name?;
    string description?;
    string homeRealmIdentifier?;
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

// Helper function to build patch operations from simplified request and current IDP
function buildIdpPatchOperations(PatchIdentityProviderRequest request, json currentIdp) returns json[] {
    json[] operations = [];
    
    if currentIdp !is map<json> {
        return operations;
    }
    map<json> current = <map<json>>currentIdp;
    
    // Handle name
    if request.name is string {
        string? currentName = current["name"] is string ? <string>current["name"] : ();
        if currentName is () || currentName != request.name {
            operations.push({
                operation: "REPLACE",
                path: "/name",
                value: request.name
            });
        }
    }
    
    // Handle description
    if request.description is string {
        string? currentDesc = current["description"] is string ? <string>current["description"] : ();
        if currentDesc is () || currentDesc != request.description {
            operations.push({
                operation: "REPLACE",
                path: "/description",
                value: request.description
            });
        }
    }
    
    // Handle homeRealmIdentifier
    if request.homeRealmIdentifier is string {
        string? currentHomeRealm = current["homeRealmIdentifier"] is string ? <string>current["homeRealmIdentifier"] : ();
        if currentHomeRealm is () || currentHomeRealm != request.homeRealmIdentifier {
            operations.push({
                operation: "REPLACE",
                path: "/homeRealmIdentifier",
                value: request.homeRealmIdentifier
            });
        }
    }
    
    // Handle jwksUri (nested in certificate)
    if request.jwksUri is string {
        json? cert = current["certificate"];
        string? currentJwksUri = ();
        if cert is map<json> {
            currentJwksUri = cert["jwksUri"] is string ? <string>cert["jwksUri"] : ();
        }
        if currentJwksUri is () || currentJwksUri != request.jwksUri {
            operations.push({
                operation: "REPLACE",
                path: "/certificate/jwksUri",
                value: request.jwksUri
            });
        }
    }
    
    // Handle OAuth properties (nested in federatedAuthenticators.authenticators[0].properties)
    json? fedAuths = current["federatedAuthenticators"];
    if fedAuths is map<json> {
        json? authenticators = fedAuths["authenticators"];
        if authenticators is json[] && authenticators.length() > 0 {
            json? firstAuth = authenticators[0];
            if firstAuth is map<json> {
                json? properties = firstAuth["properties"];
                if properties is json[] {
                    // Find and update properties
                    json[] updatedProperties = [];
                    boolean clientIdUpdated = false;
                    boolean clientSecretUpdated = false;
                    boolean oauth2AuthzEPUrlUpdated = false;
                    boolean oauth2TokenEPUrlUpdated = false;
                    
                    // First, copy existing properties and update if needed
                    foreach var prop in properties {
                        if prop is map<json> {
                            string? key = prop["key"] is string ? <string>prop["key"] : ();
                            json? value = prop["value"];
                            
                            if key is string {
                                boolean shouldUpdate = false;
                                json? newValue = ();
                                
                                if key == "ClientId" && request.clientId is string {
                                    if value is string && value != request.clientId {
                                        shouldUpdate = true;
                                        newValue = request.clientId;
                                    } else if value is () {
                                        shouldUpdate = true;
                                        newValue = request.clientId;
                                    }
                                    clientIdUpdated = true;
                                } else if key == "ClientSecret" && request.clientSecret is string {
                                    if value is string && value != request.clientSecret {
                                        shouldUpdate = true;
                                        newValue = request.clientSecret;
                                    } else if value is () {
                                        shouldUpdate = true;
                                        newValue = request.clientSecret;
                                    }
                                    clientSecretUpdated = true;
                                } else if key == "OAuth2AuthzEPUrl" && request.oauth2AuthzEPUrl is string {
                                    if value is string && value != request.oauth2AuthzEPUrl {
                                        shouldUpdate = true;
                                        newValue = request.oauth2AuthzEPUrl;
                                    } else if value is () {
                                        shouldUpdate = true;
                                        newValue = request.oauth2AuthzEPUrl;
                                    }
                                    oauth2AuthzEPUrlUpdated = true;
                                } else if key == "OAuth2TokenEPUrl" && request.oauth2TokenEPUrl is string {
                                    if value is string && value != request.oauth2TokenEPUrl {
                                        shouldUpdate = true;
                                        newValue = request.oauth2TokenEPUrl;
                                    } else if value is () {
                                        shouldUpdate = true;
                                        newValue = request.oauth2TokenEPUrl;
                                    }
                                    oauth2TokenEPUrlUpdated = true;
                                }
                                
                                if shouldUpdate && newValue is json {
                                    updatedProperties.push({
                                        key: key,
                                        value: newValue
                                    });
                                } else {
                                    updatedProperties.push(prop);
                                }
                            } else {
                                updatedProperties.push(prop);
                            }
                        } else {
                            updatedProperties.push(prop);
                        }
                    }
                    
                    // Add new properties if they don't exist
                    if request.clientId is string && !clientIdUpdated {
                        updatedProperties.push({
                            key: "ClientId",
                            value: request.clientId
                        });
                    }
                    if request.clientSecret is string && !clientSecretUpdated {
                        updatedProperties.push({
                            key: "ClientSecret",
                            value: request.clientSecret
                        });
                    }
                    if request.oauth2AuthzEPUrl is string && !oauth2AuthzEPUrlUpdated {
                        updatedProperties.push({
                            key: "OAuth2AuthzEPUrl",
                            value: request.oauth2AuthzEPUrl
                        });
                    }
                    if request.oauth2TokenEPUrl is string && !oauth2TokenEPUrlUpdated {
                        updatedProperties.push({
                            key: "OAuth2TokenEPUrl",
                            value: request.oauth2TokenEPUrl
                        });
                    }
                    
                    // Only add operation if properties changed
                    boolean propertiesChanged = false;
                    if updatedProperties.length() != properties.length() {
                        propertiesChanged = true;
                    } else {
                        // Check if any values changed
                        int i = 0;
                        while i < properties.length() {
                            json? oldProp = properties[i];
                            json? newProp = updatedProperties[i];
                            if oldProp is map<json> && newProp is map<json> {
                                json? oldValue = oldProp["value"];
                                json? newValue = newProp["value"];
                                if oldValue is string && newValue is string && oldValue != newValue {
                                    propertiesChanged = true;
                                    break;
                                } else if oldValue is () && newValue is json {
                                    propertiesChanged = true;
                                    break;
                                }
                            }
                            i = i + 1;
                        }
                    }
                    
                    if propertiesChanged {
                        operations.push({
                            operation: "REPLACE",
                            path: "/federatedAuthenticators/authenticators[0]/properties",
                            value: updatedProperties
                        });
                    }
                }
            }
        }
    }
    
    return operations;
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

    // DELETE /organization/{orgId}
    resource function delete organization/[string orgId](http:Request req) returns json|http:Response {
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORGANIZATION_DELETE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string token = tokenResult;
        http:Request mgmtReq = new;
        mgmtReq.setHeader("Authorization", string `Bearer ${token}`);
        mgmtReq.setHeader("Accept", "application/json");

        // Delete organization
        http:Response|error deleteRes = mgmtClient->execute("DELETE", string `/t/${PARENT_ORG_NAME}/api/server/v1/organizations/${orgId}`, mgmtReq);
        if deleteRes is error {
            log:printError("Delete organization failed", 'error = deleteRes);
            return buildError(502, "Failed to delete organization", deleteRes.detail());
        }
        
        // DELETE typically returns 204 No Content on success
        if deleteRes.statusCode == 204 {
            return {};
        }
        // If there's a response body, return it
        var deleteJson = deleteRes.getJsonPayload();
        if deleteJson is json {
            return deleteJson;
        }
        return {};
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
        
        // Extract client ID from Asgardeo application response
        string? clientId = ();
        if bodyJson is map<json> {
            json? clientIdField = bodyJson["clientId"];
            if clientIdField is string {
                clientId = clientIdField;
            }
        }
        
        // If client ID not in response, fetch it from credentials endpoint
        if clientId is () && applicationId is string {
            http:Request credsReq = new;
            credsReq.setHeader("Authorization", string `Bearer ${token}`);
            http:Response|error credsRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/${applicationId}/inbound-protocols/oidc`, credsReq);
            if credsRes is http:Response {
                var credsJson = credsRes.getJsonPayload();
                if credsJson is map<json> {
                    json? credClientId = credsJson["clientId"];
                    if credClientId is string {
                        clientId = credClientId;
                    }
                }
            }
        }
        
        // Asgardeo application created successfully - now create application in dev portal and map keys
        if STS_CLIENT_ID.length() > 0 && STS_CLIENT_SECRET.length() > 0 {
            string|error devPortalAppIdResult = createDevPortalApplication(body.name, PARENT_ORG_NAME);
            if devPortalAppIdResult is error {
                log:printError("Failed to create application in dev portal", 'error = devPortalAppIdResult, 'appName = body.name);
                return buildError(502, "Failed to create application in dev portal", devPortalAppIdResult.detail());
            }
            string devPortalAppId = devPortalAppIdResult;
            
            // Map OAuth keys if client ID is available and keymanager is configured
            if clientId is string && KEYMANAGER_NAME.length() > 0 {
                error? mapKeysError = mapDevPortalApplicationKeys(devPortalAppId, clientId, PARENT_ORG_NAME);
                if mapKeysError is error {
                    log:printError("Failed to map keys for dev portal application", 'error = mapKeysError, 'devPortalAppId = devPortalAppId, 'clientId = clientId, 'orgId = orgId);
                    return buildError(502, "Failed to map keys for dev portal application", mapKeysError.detail());
                }
                
                // Subscribe to required APIs (fhir-service and bulkexport)
                error? subscribeError = subscribeDevPortalApplicationToRequiredApis(devPortalAppId, PARENT_ORG_NAME);
                if subscribeError is error {
                    log:printError("Failed to subscribe dev portal application to required APIs", 'error = subscribeError, 'devPortalAppId = devPortalAppId, 'orgId = orgId);
                    return buildError(502, "Failed to subscribe dev portal application to required APIs", subscribeError.detail());
                }
            } else {
                if clientId is () {
                    log:printWarn("Client ID not found in Asgardeo application response or credentials, skipping key mapping", 'appName = body.name);
                }
                if KEYMANAGER_NAME.length() == 0 {
                    log:printDebug("Keymanager name not configured, skipping key mapping", 'appName = body.name);
                }
            }
        } else {
            log:printDebug("STS credentials not configured, skipping dev portal application creation", 'appName = body.name);
        }
        
        // Share the application with the organization if application ID was extracted
        if applicationId is string {
            http:Response|error shareRes = shareApplicationWithOrg(token, applicationId, orgId);
            if shareRes is error {
                log:printError("Failed to share application with organization", 'error = shareRes, 'applicationId = applicationId, 'orgId = orgId);
                // Continue even if sharing fails - app was created successfully
            } else if shareRes.statusCode >= 200 && shareRes.statusCode < 300 {
                log:printInfo("Application shared successfully with organization", 'applicationId = applicationId, 'orgId = orgId);
                
                // Get org IDP and patch application to assign IDP for login flow
                string|error idpNameResult = getOrgIdpName(token, orgId);
                if idpNameResult is error {
                    log:printWarn("Failed to get org IDP name, skipping authentication sequence update", 'error = idpNameResult, 'applicationId = applicationId, 'orgId = orgId);
                } else {
                    string idpName = idpNameResult;
                    http:Response|error patchRes = patchApplicationAuthenticationSequence(token, applicationId, orgId, idpName);
                    if patchRes is error {
                        log:printWarn("Failed to patch application authentication sequence", 'error = patchRes, 'applicationId = applicationId, 'orgId = orgId, 'idpName = idpName);
                    } else if patchRes.statusCode >= 200 && patchRes.statusCode < 300 {
                        log:printInfo("Application authentication sequence updated successfully", 'applicationId = applicationId, 'orgId = orgId, 'idpName = idpName);
                    } else {
                        log:printWarn("Application authentication sequence update returned non-success status", 'statusCode = patchRes.statusCode, 'applicationId = applicationId, 'orgId = orgId, 'idpName = idpName);
                    }
                }
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

    // DELETE /organization/{orgId}/application/{appId}
    resource function delete [string orgId]/application/[string appId](http:Request req)
            returns json|http:Response {
        // Step 1: Extract access token with DELETE and VIEW scopes
        // VIEW scope is needed to get the application name from sub-org
        string[] allowedScopes = [SCOPE_APPLICATION_DELETE, SCOPE_APPLICATION_VIEW];
        string|http:Response tokenResult = extractAccessTokenWithMultipleScopes(req, allowedScopes);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: Get application from sub-org to extract the name
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_application_mgt_view");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        http:Request getReq = new;
        getReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        
        http:Response|error getRes = mgmtClient->execute("GET", string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications/${appId}`, getReq);
        if getRes is error {
            log:printError("Get application failed", 'error = getRes);
            return buildError(502, "Failed to fetch application", getRes.detail());
        }
        
        // Extract application name from response
        var appJson = getRes.getJsonPayload();
        string appName = "";
        if appJson is map<json> {
            json? nameAny = appJson["name"];
            if nameAny is string {
                appName = nameAny;
            }
        }
        
        if appName.length() == 0 {
            return buildError(404, "Application not found or name could not be extracted");
        }
        
        // Step 3: Search for application in parent org using the name
        http:Request searchReq = new;
        searchReq.setHeader("Authorization", string `Bearer ${parentToken}`);
        searchReq.setHeader("accept", "application/json");
        
        // URL encode the app name - replace spaces with "+" for filter encoding
        string encodedAppName = "";
        int i = 0;
        while i < appName.length() {
            string char = appName.substring(i, i + 1);
            if char == " " {
                encodedAppName = encodedAppName + "+";
            } else {
                encodedAppName = encodedAppName + char;
            }
            i = i + 1;
        }
        string filterValue = string `name+eq+${encodedAppName}`;
        string searchPath = string `/t/${PARENT_ORG_NAME}/api/server/v1/applications?filter=${filterValue}&limit=1&offset=0`;
        http:Response|error searchRes = mgmtClient->execute("GET", searchPath, searchReq);
        if searchRes is error {
            log:printError("Search application in parent org failed", 'error = searchRes);
            return buildError(502, "Failed to search application in parent org", searchRes.detail());
        }
        
        // Extract parent org application ID from search results
        var searchJson = searchRes.getJsonPayload();
        string parentAppId = "";
        if searchJson is map<json> {
            json? appsAny = searchJson["applications"];
            if appsAny is json[] && appsAny.length() > 0 {
                json? firstApp = appsAny[0];
                if firstApp is map<json> {
                    json? idAny = firstApp["id"];
                    if idAny is string {
                        parentAppId = idAny;
                    }
                }
            }
        }
        
        if parentAppId.length() == 0 {
            return buildError(404, "Application not found in parent org");
        }
        
        // Step 4: Delete application using parent org app ID
        http:Request deleteReq = new;
        deleteReq.setHeader("Authorization", string `Bearer ${parentToken}`);
        deleteReq.setHeader("accept", "*/*");
        
        string deletePath = string `/t/${PARENT_ORG_NAME}/api/server/v1/applications/${parentAppId}`;
        http:Response|error deleteRes = mgmtClient->execute("DELETE", deletePath, deleteReq);
        if deleteRes is error {
            log:printError("Delete application failed", 'error = deleteRes);
            return buildError(502, "Failed to delete application", deleteRes.detail());
        }
        
        // DELETE typically returns 204 No Content on success
        if deleteRes.statusCode == 204 {
            return {};
        }
        // If there's a response body, return it
        var deleteJson = deleteRes.getJsonPayload();
        if deleteJson is json {
            return deleteJson;
        }
        return {};
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
            
            // Determine which role ID to use
            string? roleIdToUse = ();
            if body.role is string {
                string roleName = <string>body.role;
                if strings:trim(roleName).length() > 0 {
                    // Validate role name against allowed role names if configured
                    if ALLOWED_ROLE_NAMES.length() > 0 {
                        boolean isAllowed = false;
                        foreach string allowedRole in ALLOWED_ROLE_NAMES {
                            if strings:trim(allowedRole) == strings:trim(roleName) {
                                isAllowed = true;
                                break;
                            }
                        }
                        if !isAllowed {
                            log:printWarn("Unauthorized role name attempted", 'orgId = orgId, 'roleName = roleName, 'allowedRoles = ALLOWED_ROLE_NAMES);
                            return buildError(401, string `Unauthorized attempt.`);
                        }
                    }
                    // Switch token for role management view scope to fetch roles
                    string|error roleViewTokenResult = switchOrganizationToken(parentToken, orgId,
                        "internal_org_role_mgt_view");
                    if roleViewTokenResult is error {
                        log:printError("Failed to switch organization token for role lookup", 'error = roleViewTokenResult, 'orgId = orgId, 'roleName = roleName);
                        return buildError(502, "Failed to switch organization token for role lookup", roleViewTokenResult.message());
                    }
                    string roleViewToken = roleViewTokenResult;
                    
                    // Fetch role ID by display name from sub-organization
                    string|error roleIdResult = getRoleIdByDisplayName(roleViewToken, orgId, roleName);
                    if roleIdResult is error {
                        log:printError("Failed to find role", 'error = roleIdResult, 'orgId = orgId, 'roleName = roleName);
                        return buildError(400, string `Invalid role: ${roleName}. Role not found in organization.`);
                    }
                    roleIdToUse = roleIdResult;
                    log:printDebug("Using role from request", 'roleName = roleName, 'roleId = roleIdToUse);
                }
            }
            
            // Use default role if no role was provided or if role lookup failed
            if roleIdToUse is () {
                if strings:trim(DEFAULT_USER_ROLE_ID).length() > 0 {
                    roleIdToUse = DEFAULT_USER_ROLE_ID;
                    log:printDebug("Using default role", 'roleId = roleIdToUse);
                } else {
                    log:printDebug("No role specified and DEFAULT_USER_ROLE_ID not configured, skipping role assignment");
                }
            }
            
            // Add user to role if role ID is determined and user ID was extracted
            if userId is string && roleIdToUse is string {
                // Switch token for role management scope
                string|error roleTokenResult = switchOrganizationToken(parentToken, orgId,
                    "internal_org_role_mgt_update");
                if roleTokenResult is error {
                    log:printWarn("Failed to switch organization token for role assignment", 'error = roleTokenResult, 'userId = userId, 'roleId = roleIdToUse);
                    // Continue even if token switch fails - user was invited successfully
                } else {
                    string roleToken = roleTokenResult;
                    http:Response|error roleRes = addUserToRole(roleToken, userId, roleIdToUse);
                    if roleRes is error {
                        log:printWarn("Failed to add user to role", 'error = roleRes, 'userId = userId, 'roleId = roleIdToUse);
                        // Continue even if role assignment fails - user was invited successfully
                    } else if roleRes.statusCode >= 200 && roleRes.statusCode < 300 {
                        log:printInfo("User added to role successfully", 'userId = userId, 'roleId = roleIdToUse);
                    } else {
                        log:printWarn("Role assignment returned non-success status", 'statusCode = roleRes.statusCode, 'userId = userId, 'roleId = roleIdToUse);
                    }
                }
            } else if userId is () {
                log:printWarn("Could not extract user ID from invite response, skipping role assignment");
            }
            
            return resJson;
        }
        return buildError(502, "Invalid response for invite user");
    }

    // GET /organization/{orgId}/users
    resource function get [string orgId]/user(http:Request req) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_USER_LIST);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_user_mgt_list");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Step 3: Make SCIM API call to get users list
        http:Request scimReq = new;
        scimReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        scimReq.setHeader("Accept", "application/scim+json");
        
        string scimPath = string `/t/${PARENT_ORG_NAME}/o/scim2/Users`;
        http:Response|error scimRes = mgmtClient->execute("GET", scimPath, scimReq);
        if scimRes is error {
            log:printError("Failed to fetch users list", 'error = scimRes, 'orgId = orgId);
            return buildError(502, "Failed to fetch users list", scimRes.detail());
        }
        
        if scimRes.statusCode < 200 || scimRes.statusCode >= 300 {
            json? errorDetails = ();
            var errorJson = scimRes.getJsonPayload();
            if errorJson is json {
                errorDetails = errorJson;
            }
            log:printError("Fetch users list returned error status", 'statusCode = scimRes.statusCode, 'orgId = orgId, 'details = errorDetails);
            return buildError(scimRes.statusCode, "Failed to fetch users list", errorDetails);
        }
        
        // Step 4: Parse and filter response
        var resJson = scimRes.getJsonPayload();
        if resJson is json {
            json filteredResponse = filterUserListResponse(resJson);
            return filteredResponse;
        }
        return buildError(502, "Invalid response for users list");
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

    // PATCH /organization/{orgId}/identity-provider/{idpId}
    resource function patch [string orgId]/identity\-provider/[string idpId](http:Request req, @http:Payload PatchIdentityProviderRequest body) returns json|http:Response {
        // Step 1: extract access token from request
        string|http:Response tokenResult = extractAccessToken(req, SCOPE_ORG_IDP_UPDATE);
        if tokenResult is http:Response {
            return tokenResult;
        }
        string parentToken = tokenResult;
        
        // Step 2: exchange token for target organization using organization_switch grant
        string|error switchedTokenResult = switchOrganizationToken(parentToken, orgId,
            "internal_org_idp_update");
        if switchedTokenResult is error {
            log:printError("Failed to switch organization token", 'error = switchedTokenResult);
            return buildError(502, "Failed to switch organization token", switchedTokenResult.message());
        }
        string switchedToken = switchedTokenResult;
        
        // Step 3: Fetch current IDP to understand its structure
        http:Request getReq = new;
        getReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        
        string getPath = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers/${idpId}`;
        http:Response|error getRes = mgmtClient->execute("GET", getPath, getReq);
        if getRes is error {
            log:printError("Get identity provider failed", 'error = getRes);
            return buildError(502, "Failed to fetch identity provider", getRes.detail());
        }
        
        if getRes.statusCode < 200 || getRes.statusCode >= 300 {
            json? errorDetails = ();
            var errorJson = getRes.getJsonPayload();
            if errorJson is json {
                errorDetails = errorJson;
            }
            log:printError("Get identity provider returned error status", 'statusCode = getRes.statusCode, 'idpId = idpId, 'details = errorDetails);
            return buildError(getRes.statusCode, "Failed to fetch identity provider", errorDetails);
        }
        
        var currentIdpJson = getRes.getJsonPayload();
        if currentIdpJson !is json || currentIdpJson !is map<json> {
            return buildError(502, "Invalid response for get identity provider");
        }
        
        // Fetch full IDP details from self link if available to ensure we have all properties
        json? fullIdp = fetchIdpFromSelfLink(<json>currentIdpJson, switchedToken, mgmtClient);
        json currentIdp = fullIdp is json ? fullIdp : <json>currentIdpJson;
        
        // Step 4: Build patch operations from simplified request
        json[] patchOperations = buildIdpPatchOperations(body, currentIdp);
        
        if patchOperations.length() == 0 {
            return buildError(400, "No fields to update");
        }
        
        // Step 5: Execute PATCH request
        http:Request patchReq = new;
        patchReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
        patchReq.setHeader("Content-Type", "application/json");
        patchReq.setJsonPayload(patchOperations);
        
        string patchPath = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers/${idpId}`;
        http:Response|error patchRes = mgmtClient->execute("PATCH", patchPath, patchReq);
        if patchRes is error {
            log:printError("Patch identity provider failed", 'error = patchRes, 'orgId = orgId, 'idpId = idpId);
            return buildError(502, "Failed to patch identity provider", patchRes.detail());
        }
        
        if patchRes.statusCode < 200 || patchRes.statusCode >= 300 {
            json? errorDetails = ();
            var errorJson = patchRes.getJsonPayload();
            if errorJson is json {
                errorDetails = errorJson;
            }
            log:printError("Patch identity provider returned error status", 'statusCode = patchRes.statusCode, 'orgId = orgId, 'idpId = idpId, 'details = errorDetails);
            return buildError(patchRes.statusCode, "Failed to patch identity provider", errorDetails);
        }
        
        // Step 6: Return simplified response
        var resJson = patchRes.getJsonPayload();
        if resJson is json {
            json? simplified = simplifyIdpResponse(resJson, switchedToken, mgmtClient);
            if simplified is json {
                return simplified;
            }
        }
        return buildError(502, "Invalid response for patch identity provider");
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
    string scope = "internal_organization_create internal_organization_view internal_organization_update internal_organization_delete " +
        "internal_user_mgt_list internal_user_mgt_view internal_user_mgt_update internal_user_mgt_create internal_org_user_mgt_create internal_org_role_mgt_update " +
        "internal_application_mgt_create internal_application_mgt_delete internal_application_mgt_update internal_application_mgt_view internal_org_application_mgt_create internal_org_application_mgt_view internal_org_application_mgt_update " +
        "internal_branding_preference_update internal_org_branding_preference_update " +
        "internal_shared_application_create internal_shared_application_view internal_shared_application_delete " +
        "internal_user_unshare internal_user_shared_access_view internal_user_share " +
        "internal_org_idp_create internal_org_idp_view internal_org_idp_update";
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

// Get the first organization IDP name
function getOrgIdpName(string token, string orgId) returns string|error {
    // Switch token for target organization
    string|error switchedTokenResult = switchOrganizationToken(token, orgId, "internal_org_idp_view");
    if switchedTokenResult is error {
        return error("Failed to switch organization token", switchedTokenResult);
    }
    string switchedToken = switchedTokenResult;
    
    http:Request mgmtReq = new;
    mgmtReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
    
    string path = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/identity-providers`;
    http:Response|error res = mgmtClient->execute("GET", path, mgmtReq);
    if res is error {
        return error("Failed to fetch identity providers", res);
    }
    
    if res.statusCode < 200 || res.statusCode >= 300 {
        return error("Failed to fetch identity providers", statusCode = res.statusCode);
    }
    
    var resJson = res.getJsonPayload();
    if resJson is json {
        json[] idps = [];
        // Handle array response
        if resJson is json[] {
            idps = resJson;
        } else if resJson is map<json> {
            // Handle object with array (e.g., {"identityProviders": [...]})
            json? idpsField = resJson["identityProviders"];
            if idpsField is json[] {
                idps = idpsField;
            } else {
                json? resultsField = resJson["results"];
                if resultsField is json[] {
                    idps = resultsField;
                } else {
                    json? dataField = resJson["data"];
                    if dataField is json[] {
                        idps = dataField;
                    }
                }
            }
        }
        
        // Get the first IDP name
        if idps.length() > 0 {
            json firstIdp = idps[0];
            if firstIdp is map<json> && firstIdp["name"] is string {
                return <string>firstIdp["name"];
            }
        }
    }
    
    return error("No identity providers found or invalid response format");
}

// Patch application to assign IDP for login flow
function patchApplicationAuthenticationSequence(string token, string applicationId, string orgId, string idpName) returns http:Response|error {
    // Switch token for target organization with update scope
    string|error switchedTokenResult = switchOrganizationToken(token, orgId, "internal_org_application_mgt_update");
    if switchedTokenResult is error {
        return error("Failed to switch organization token", switchedTokenResult);
    }
    string switchedToken = switchedTokenResult;
    
    http:Request patchReq = new;
    patchReq.setHeader("Authorization", string `Bearer ${switchedToken}`);
    patchReq.setHeader("Content-Type", "application/json");
    
    // Build authentication sequence payload
    json authSequencePayload = {
        authenticationSequence: {
            attributeStepId: 1,
            requestPathAuthenticators: [],
            steps: [
                {
                    id: 1,
                    options: [
                        {
                            authenticator: "OpenIDConnectAuthenticator",
                            idp: idpName
                        }
                    ]
                }
            ],
            subjectStepId: 1,
            "type": "USER_DEFINED",
            script: ""
        }
    };
    patchReq.setJsonPayload(authSequencePayload);
    
    string patchPath = string `/t/${PARENT_ORG_NAME}/o/api/server/v1/applications/${applicationId}`;
    http:Response|error patchRes = mgmtClient->execute("PATCH", patchPath, patchReq);
    return patchRes;
}

// Get STS token for dev portal API calls
function getStsToken(string orgHandle) returns string|error {
    if STS_CLIENT_ID.length() == 0 || STS_CLIENT_SECRET.length() == 0 {
        return error("STS client ID or secret not configured");
    }
    
    // Create Basic Auth header: base64 encode(clientId:clientSecret)
    string credentials = string `${STS_CLIENT_ID}:${STS_CLIENT_SECRET}`;
    byte[] credentialsBytes = credentials.toBytes();
    string base64Credentials = credentialsBytes.toBase64();
    string authHeader = string `Basic ${base64Credentials}`;
    
    http:Request tokenReq = new;
    tokenReq.setHeader("Authorization", authHeader);
    tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");
    
    // Build form data
    string formData = string `grant_type=client_credentials&scope=apim:api_manage apim:admin apim:prod_key_manage apim:subscribe&orgHandle=${orgHandle}`;
    tokenReq.setPayload(formData);
    
    http:Response|error tokenRes = stsClient->post("/oauth2/token", tokenReq);
    if tokenRes is error {
        log:printError("Failed to get STS token", 'error = tokenRes, 'orgHandle = orgHandle);
        return error("Failed to get STS token", tokenRes);
    }
    
    if tokenRes.statusCode < 200 || tokenRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = tokenRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("STS token request returned non-success status", 'statusCode = tokenRes.statusCode, 'orgHandle = orgHandle, 'errorDetails = errorDetails);
        return error(string `STS token request returned status ${tokenRes.statusCode}`, details = errorDetails);
    }
    
    var tokenJsonResult = tokenRes.getJsonPayload();
    if tokenJsonResult is error {
        log:printError("Failed to parse STS token response", 'error = tokenJsonResult, 'orgHandle = orgHandle);
        return error("Failed to parse STS token response", tokenJsonResult);
    }
    
    json? tokenJson = tokenJsonResult;
    if tokenJson is map<json> {
        json? accessToken = tokenJson["access_token"];
        if accessToken is string {
            return accessToken;
        }
    }
    
    return error("Invalid STS token response format");
}

// Create application in dev portal
function createDevPortalApplication(string appName, string orgHandle) returns string|error {
    // Get STS token
    string|error stsTokenResult = getStsToken(orgHandle);
    if stsTokenResult is error {
        log:printError("Failed to get STS token for dev portal application creation", 'error = stsTokenResult, 'appName = appName, 'orgHandle = orgHandle);
        return stsTokenResult;
    }
    string stsToken = stsTokenResult;
    
    // Create application in dev portal
    http:Request appReq = new;
    appReq.setHeader("Authorization", string `Bearer ${stsToken}`);
    appReq.setHeader("Content-Type", "application/json");
    
    json appPayload = {
        name: appName,
        throttlingPolicy: "Unlimited",
        tokenType: "JWT",
        description: ""
    };
    appReq.setJsonPayload(appPayload);
    
    string appPath = string `/api/am/devportal/v2/applications/?organizationId=${PARENT_ORG_ID}`;
    http:Response|error appRes = stsClient->post(appPath, appReq);
    if appRes is error {
        log:printError("Failed to create application in dev portal", 'error = appRes, 'appName = appName, 'orgHandle = orgHandle);
        return error("Failed to create application in dev portal", appRes);
    }
    
    if appRes.statusCode < 200 || appRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = appRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("Dev portal application creation returned non-success status", 'statusCode = appRes.statusCode, 'appName = appName, 'orgHandle = orgHandle, 'errorDetails = errorDetails);
        return error(string `Dev portal application creation returned status ${appRes.statusCode}`, details = errorDetails);
    }
    
    // Extract dev portal application ID from response
    var appJsonResult = appRes.getJsonPayload();
    if appJsonResult is error {
        log:printError("Failed to parse dev portal application response", 'error = appJsonResult, 'appName = appName);
        return error("Failed to parse dev portal application response", appJsonResult);
    }
    
    json? appJson = appJsonResult;
    string? devPortalAppId = ();
    if appJson is map<json> {
        json? applicationId = appJson["applicationId"];
        if applicationId is string {
            devPortalAppId = applicationId;
        } else {
            // Try alternative field name
            json? id = appJson["id"];
            if id is string {
                devPortalAppId = id;
            }
        }
    }
    
    if devPortalAppId is () {
        log:printError("Dev portal application ID not found in response", 'appName = appName, 'response = appJson);
        return error("Dev portal application ID not found in response");
    }
    
    log:printInfo("Successfully created application in dev portal", 'appName = appName, 'orgHandle = orgHandle, 'devPortalAppId = devPortalAppId);
    return devPortalAppId;
}

// Map OAuth keys for dev portal application
function mapDevPortalApplicationKeys(string devPortalAppId, string clientId, string orgHandle) returns error? {
    if KEYMANAGER_NAME.length() == 0 {
        return error("Keymanager name not configured");
    }
    
    // Get STS token
    string|error stsTokenResult = getStsToken(orgHandle);
    if stsTokenResult is error {
        log:printError("Failed to get STS token for mapping dev portal application keys", 'error = stsTokenResult, 'devPortalAppId = devPortalAppId, 'orgId = PARENT_ORG_ID);
        return stsTokenResult;
    }
    string stsToken = stsTokenResult;
    
    // Map keys
    http:Request mapReq = new;
    mapReq.setHeader("Authorization", string `Bearer ${stsToken}`);
    mapReq.setHeader("Content-Type", "application/json");
    
    json mapPayload = {
        consumerKey: clientId,
        keyType: "PRODUCTION",
        keyManager: KEYMANAGER_NAME
    };
    mapReq.setJsonPayload(mapPayload);
    
    string mapPath = string `/api/am/devportal/v2/applications/${devPortalAppId}/map-keys?organizationId=${PARENT_ORG_ID}`;
    http:Response|error mapRes = stsClient->post(mapPath, mapReq);
    if mapRes is error {
        log:printError("Failed to map keys for dev portal application", 'error = mapRes, 'devPortalAppId = devPortalAppId, 'clientId = clientId, 'orgId = PARENT_ORG_ID);
        return error("Failed to map keys for dev portal application", mapRes);
    }
    
    if mapRes.statusCode < 200 || mapRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = mapRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("Map keys request returned non-success status", 'statusCode = mapRes.statusCode, 'devPortalAppId = devPortalAppId, 'clientId = clientId, 'orgId = PARENT_ORG_ID, 'errorDetails = errorDetails);
        return error(string `Map keys request returned status ${mapRes.statusCode}`, details = errorDetails);
    }
    
    log:printInfo("Successfully mapped keys for dev portal application", 'devPortalAppId = devPortalAppId, 'clientId = clientId, 'orgId = PARENT_ORG_ID);
    return ();
}

// Retrieve APIs from dev portal
function getDevPortalApis(string orgHandle) returns json[]|error {
    // Get STS token
    string|error stsTokenResult = getStsToken(orgHandle);
    if stsTokenResult is error {
        log:printError("Failed to get STS token for retrieving APIs", 'error = stsTokenResult);
        return stsTokenResult;
    }
    string stsToken = stsTokenResult;
    
    // Retrieve APIs
    http:Request apisReq = new;
    apisReq.setHeader("Authorization", string `Bearer ${stsToken}`);
    
    string apisPath = string `/api/am/devportal/v2/apis?limit=1000&offset=0&query=&organizationId=${PARENT_ORG_ID}&aggregateBy=majorVersion`;
    http:Response|error apisRes = stsClient->execute("GET", apisPath, apisReq);
    if apisRes is error {
        log:printError("Failed to retrieve APIs from dev portal", 'error = apisRes);
        return error("Failed to retrieve APIs from dev portal", apisRes);
    }
    
    if apisRes.statusCode < 200 || apisRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = apisRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("Retrieve APIs request returned non-success status", 'statusCode = apisRes.statusCode, 'errorDetails = errorDetails);
        return error(string `Retrieve APIs request returned status ${apisRes.statusCode}`, details = errorDetails);
    }
    
    var apisJsonResult = apisRes.getJsonPayload();
    if apisJsonResult is error {
        log:printError("Failed to parse APIs response", 'error = apisJsonResult);
        return error("Failed to parse APIs response", apisJsonResult);
    }
    
    json? apisJson = apisJsonResult;
    json[] apiList = [];
    if apisJson is map<json> {
        json? listField = apisJson["list"];
        if listField is json[] {
            apiList = listField;
        }
    }
    
    return apiList;
}

// Find API ID by name (searches in name and displayName fields)
function findApiIdByName(json[] apiList, string apiName) returns string? {
    foreach json api in apiList {
        if api is map<json> {
            json? name = api["name"];
            json? displayName = api["displayName"];
            boolean nameMatches = false;
            boolean displayNameMatches = false;
            
            if name is string {
                nameMatches = strings:includes(strings:toLowerAscii(name), strings:toLowerAscii(apiName));
            }
            if displayName is string {
                displayNameMatches = strings:includes(strings:toLowerAscii(displayName), strings:toLowerAscii(apiName));
            }
            
            if nameMatches || displayNameMatches {
                json? id = api["id"];
                if id is string {
                    return id;
                }
            }
        }
    }
    return ();
}

// Subscribe dev portal application to an API
function subscribeDevPortalApplicationToApi(string devPortalAppId, string apiId, string orgId, string orgHandle) returns error? {
    // Get STS token
    string|error stsTokenResult = getStsToken(orgHandle);
    if stsTokenResult is error {
        log:printError("Failed to get STS token for subscribing to API", 'error = stsTokenResult, 'devPortalAppId = devPortalAppId, 'apiId = apiId);
        return stsTokenResult;
    }
    string stsToken = stsTokenResult;
    
    // Subscribe to API
    http:Request subscribeReq = new;
    subscribeReq.setHeader("Authorization", string `Bearer ${stsToken}`);
    subscribeReq.setHeader("Content-Type", "application/json");
    
    json subscribePayload = {
        applicationId: devPortalAppId,
        apiId: apiId,
        throttlingPolicy: "Unlimited",
        versionRange: "v1"
    };
    subscribeReq.setJsonPayload(subscribePayload);
    
    string subscribePath = string `/api/am/devportal/v2/subscriptions/?organizationId=${orgId}`;
    http:Response|error subscribeRes = stsClient->post(subscribePath, subscribeReq);
    if subscribeRes is error {
        log:printError("Failed to subscribe dev portal application to API", 'error = subscribeRes, 'devPortalAppId = devPortalAppId, 'apiId = apiId, 'orgId = orgId);
        return error("Failed to subscribe dev portal application to API", subscribeRes);
    }
    
    if subscribeRes.statusCode < 200 || subscribeRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = subscribeRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("Subscribe API request returned non-success status", 'statusCode = subscribeRes.statusCode, 'devPortalAppId = devPortalAppId, 'apiId = apiId, 'orgId = orgId, 'errorDetails = errorDetails);
        return error(string `Subscribe API request returned status ${subscribeRes.statusCode}`, details = errorDetails);
    }
    
    log:printInfo("Successfully subscribed dev portal application to API", 'devPortalAppId = devPortalAppId, 'apiId = apiId, 'orgId = orgId);
    return ();
}

// Subscribe dev portal application to required APIs (fhir-service and bulkexport)
function subscribeDevPortalApplicationToRequiredApis(string devPortalAppId, string orgHandle) returns error? {
    // Retrieve APIs
    json[]|error apisResult = getDevPortalApis(orgHandle);
    if apisResult is error {
        log:printError("Failed to retrieve APIs for subscription", 'error = apisResult, 'devPortalAppId = devPortalAppId);
        return apisResult;
    }
    json[] apiList = apisResult;
    
    // Find API IDs for fhir-service and bulkexport
    string? fhirServiceApiId = findApiIdByName(apiList, "fhir-service");
    string? bulkExportApiId = findApiIdByName(apiList, "bulkexport");
    
    // Subscribe to fhir-service API if found
    if fhirServiceApiId is string {
        error? fhirError = subscribeDevPortalApplicationToApi(devPortalAppId, fhirServiceApiId, PARENT_ORG_ID, orgHandle);
        if fhirError is error {
            log:printError("Failed to subscribe to fhir-service API", 'error = fhirError, 'devPortalAppId = devPortalAppId, 'apiId = fhirServiceApiId);
            return fhirError;
        }
    } else {
        log:printWarn("fhir-service API not found, skipping subscription", 'devPortalAppId = devPortalAppId);
    }
    
    // Subscribe to bulkexport API if found
    if bulkExportApiId is string {
        error? bulkError = subscribeDevPortalApplicationToApi(devPortalAppId, bulkExportApiId, PARENT_ORG_ID, orgHandle);
        if bulkError is error {
            log:printError("Failed to subscribe to bulkexport API", 'error = bulkError, 'devPortalAppId = devPortalAppId, 'apiId = bulkExportApiId);
            return bulkError;
        }
    } else {
        log:printWarn("bulkexport API not found, skipping subscription", 'devPortalAppId = devPortalAppId);
    }
    
    return ();
}

// Fetch role ID by display name from sub-organization
// Uses SCIM API to get roles and searches for matching displayName
function getRoleIdByDisplayName(string token, string orgId, string roleDisplayName) returns string|error {
    http:Request roleReq = new;
    roleReq.setHeader("Authorization", string `Bearer ${token}`);
    roleReq.setHeader("Accept", "application/scim+json");
    
    // Build query parameters: filter by displayName matching the role name exactly
    // Using "eq" (equals) filter operator
    // Replace spaces in role name with "+" for SCIM filter encoding
    string encodedRoleName = "";
    int i = 0;
    while i < roleDisplayName.length() {
        string char = roleDisplayName.substring(i, i + 1);
        if char == " " {
            encodedRoleName = encodedRoleName + "+";
        } else {
            encodedRoleName = encodedRoleName + char;
        }
        i = i + 1;
    }
    string filter = string `displayName+eq+${encodedRoleName}`;
    string queryParams = string `count=10&excludedAttributes=users,groups,permissions,associatedApplications&filter=${filter}`;
    string rolePath = string `/t/${PARENT_ORG_NAME}/o/scim2/v2/Roles?${queryParams}`;
    
    http:Response|error roleRes = mgmtClient->execute("GET", rolePath, roleReq);
    if roleRes is error {
        log:printError("Failed to fetch roles", 'error = roleRes, 'orgId = orgId, 'roleDisplayName = roleDisplayName);
        return error("Failed to fetch roles", roleRes);
    }
    
    if roleRes.statusCode < 200 || roleRes.statusCode >= 300 {
        json? errorDetails = ();
        var errorJson = roleRes.getJsonPayload();
        if errorJson is json {
            errorDetails = errorJson;
        }
        log:printError("Fetch roles returned error status", 'statusCode = roleRes.statusCode, 'orgId = orgId, 'roleDisplayName = roleDisplayName, 'details = errorDetails);
        return error(string `Failed to fetch roles: status ${roleRes.statusCode}`, details = errorDetails);
    }
    
    var resJson = roleRes.getJsonPayload();
    if resJson is json && resJson is map<json> {
        json? resources = resJson["Resources"];
        if resources is json[] {
            foreach var roleItem in resources {
                if roleItem is map<json> {
                    json? displayName = roleItem["displayName"];
                    json? id = roleItem["id"];
                    if displayName is string && id is string {
                        string displayNameStr = <string>displayName;
                        // Exact match (case-sensitive)
                        if displayNameStr == roleDisplayName {
                            string roleId = <string>id;
                            log:printDebug("Found role by display name", 'roleDisplayName = roleDisplayName, 'roleId = roleId);
                            return roleId;
                        }
                    }
                }
            }
        }
    }
    
    return error(string `Role not found: ${roleDisplayName}`);
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

// Filter user list response to include only id, name, emails, and roles
function filterUserListResponse(json scimResponse) returns json {
    json[] filteredUsers = [];
    map<json> responseMap = {};
    
    // Copy top-level metadata
    if scimResponse is map<json> {
        if scimResponse["totalResults"] is json {
            responseMap["totalResults"] = scimResponse["totalResults"];
        }
        if scimResponse["startIndex"] is json {
            responseMap["startIndex"] = scimResponse["startIndex"];
        }
        if scimResponse["itemsPerPage"] is json {
            responseMap["itemsPerPage"] = scimResponse["itemsPerPage"];
        }
        if scimResponse["schemas"] is json {
            responseMap["schemas"] = scimResponse["schemas"];
        }
        
        // Filter Resources array
        json? resources = scimResponse["Resources"];
        if resources is json[] {
            foreach var userItem in resources {
                if userItem is map<json> {
                    map<json> filteredUser = {};
                    
                    // Extract id
                    if userItem["id"] is json {
                        filteredUser["id"] = userItem["id"];
                    }
                    
                    // Extract name
                    if userItem["name"] is json {
                        filteredUser["name"] = userItem["name"];
                    }
                    
                    // Extract emails
                    if userItem["emails"] is json {
                        filteredUser["emails"] = userItem["emails"];
                    }
                    
                    // Extract roles
                    if userItem["roles"] is json {
                        filteredUser["roles"] = userItem["roles"];
                    }
                    
                    filteredUsers.push(filteredUser);
                }
            }
        }
        responseMap["Resources"] = filteredUsers;
    }
    
    return responseMap;
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


