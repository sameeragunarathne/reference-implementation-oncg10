// Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.

// This software is the property of WSO2 LLC. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein is strictly forbidden, unless permitted by WSO2 in accordance with
// the WSO2 Software License available at: https://wso2.com/licenses/eula/3.2
// For specific language governing the permissions and limitations under
// this license, please see the license as well as any agreement you’ve
// entered into with WSO2 governing the purchase of this software and any
// associated services.

import ballerina/http;

configurable string backendBaseUrl = "http://localhost:9300/backend";
configurable string fhirBaseUrl = "localhost:9102/fhir/r4";
final http:Client fhirApiClient = check new (fhirBaseUrl);
final http:Client backendClient = check new (backendBaseUrl);

public const CAPABILITY_STATEMENT = "CapabilityStatement";
public const OPERATION_OUTCOME = "OperationOutcome";
public const REST_MODE_SERVER = "server";
public const REST_MODE_CLIENT = "client";
public const SECURITY_TOKEN = "token";
public const SECURITY_REVOKE = "revoke";
public const SECURITY_AUTHORIZE = "authorize";
public const SECURITY_INTROSPECT = "introspect";
public const SECURITY_REGISTER = "register";
public const SECURITY_MANAGE = "manage";
public const SECURITY_EXT_URL = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris";
public const SECURITY_EXT_VALUEURL = "valueUri";
public const SERVICE_SYSTEM = "http://terminology.hl7.org/CodeSystem/restful-security-service";
public const SERVICE_CODE = "SMART-on-FHIR";
public const SERVICE_DISPLAY = "SMART-on-FHIR";

public const VALUE_NOT_FOUND = "Value not found";
public const INTERNAL_SERVER_ERROR = "Internal server error occured";
public const ERROR_OCCURRED = "Error occurred";
public const CAPABILITY_STATEMENT_FAILED = "Capability statement generation failed";
public const CONTACT_SERVER_ADMIN = "Please contact server admin if the issue persists";

public const SMART_CONFIGURATION = "SmartConfiguration";
public const SMART_CONFIGURATION_FAILED = "Smart configuration generation failed";
