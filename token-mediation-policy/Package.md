# Token Response Mediation Policy

## Overview

The Token Response Mediation Policy is a Ballerina-based API mediation policy designed for Choreo API Manager. This policy enhances OAuth2 token responses by adding additional metadata required for SMART on FHIR applications, specifically `smart_style_url` and `need_patient_banner` fields.

## Features

- **Response Enhancement**: Automatically adds SMART on FHIR specific fields to OAuth2 token responses
- **Flexible Flow Support**: Supports request, response, and fault flow mediation
- **Healthcare Compliance**: Designed for healthcare applications following SMART on FHIR standards
- **Observability**: Built with observability features enabled for monitoring and debugging

## Policy Flows

This mediation policy implements the following flows:

### Response Flow (`policyNameOut`)
- **Purpose**: Modifies the OAuth2 token response payload
- **Functionality**: 
  - Adds `smart_style_url` pointing to SMART Health IT CSS styles
  - Sets `need_patient_banner` to `false` for simplified UI
- **Trigger**: Executed when processing responses from the upstream authorization server

### Request Flow (`policyNameIn`)
- **Purpose**: Placeholder for request processing (currently pass-through)
- **Functionality**: No modifications applied to incoming requests
- **Trigger**: Executed on incoming authorization requests

### Fault Flow (`policyNameFault`)
- **Purpose**: Error handling for policy execution
- **Functionality**: Placeholder for custom error handling logic
- **Trigger**: Executed when errors occur during request/response processing

## Configuration

The policy is configured through the `Ballerina.toml` file:

- **Organization**: `wso2healthcare`
- **Package Name**: `tokenResponseMediationPolicy`
- **Version**: `1.0.4`
- **Ballerina Distribution**: `2201.5.5`

### Keywords
- `choreo-apim-mediation-policy`: Identifies this as a Choreo API Manager mediation policy
- `choreo-apim-mediation-request-flow`: Supports request flow mediation
- `choreo-apim-mediation-response-flow`: Supports response flow mediation
- `choreo-apim-mediation-fault-flow`: Supports fault flow mediation

## Usage

1. **Deploy the Policy**: Upload the compiled policy package to Choreo API Manager
2. **Apply to API**: Attach the policy to your OAuth2 token endpoint API
3. **Configure Placement**: Ensure the policy is applied in the response flow
4. **Monitor**: Use the built-in observability features to monitor policy execution

## Dependencies

- **Ballerina HTTP Module**: For HTTP request/response handling
- **Ballerina Log Module**: For logging and debugging
- **Choreo Mediation Module**: For Choreo-specific mediation capabilities

## SMART on FHIR Integration

This policy specifically enhances OAuth2 token responses for SMART on FHIR applications by:

- Adding standardized styling information (`smart_style_url`)
- Configuring patient banner display preferences (`need_patient_banner`)
- Ensuring compliance with SMART App Launch Framework requirements

## Development Notes

- The policy functions can be renamed as needed while maintaining the required annotations
- Additional parameters can be added to policy functions (supported types: `int`, `string`, `float`, `boolean`, `decimal`)
- All policy functions must have the same parameter signature for consistency
- Observability is enabled by default for production monitoring
