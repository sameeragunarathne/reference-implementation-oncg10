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
import ballerina/io;

# A service representing a network-accessible API
# bound to port `9090`.
service /backend on new http:Listener(9300) {

    # A resource for retrieving all the fhir resources
    #
    # + resourceType - fhir resource type
    # + return - json array of fhir resources
    isolated resource function get data/[string resourceType]() returns json[]|error {

        lock {
            if (!dataMap.hasKey(resourceType.toLowerAscii())) {
                return [];
            }
            json|error dataJson = io:fileReadJson(dataMap.get(resourceType.toLowerAscii()));
            if (dataJson is json) {
                json[]|error resultSet = dataJson.data.ensureType();
                if (resultSet is json[]) {
                    return resultSet;
                }
            }
            return [];
        }
    }

    # A resource for retrieving legacy format health resources
    #
    # + resourceType - fhir resource type
    # + return - json array of fhir resources
    isolated resource function get data/legacy/[string resourceType]() returns json[]|error {
        // This is a sample implementation for the legacy resource retrieval
        // Only supports patient data retrieval
        lock {
            if resourceType.toLowerAscii() != "patient" {
                return [];
            }
            json|error dataJson = io:fileReadJson("patientlegacy.json");
            if (dataJson is json) {
                json[]|error resultSet = dataJson.data.ensureType();
                if (resultSet is json[]) {
                    return resultSet;
                }
            }
            return [];
        }
    }

}

final map<string> & readonly dataMap = {
    "allergyintolerance": "allergyintolerance.json",
    "careplan": "careplan.json",
    "careteam": "careteam.json",
    "condition": "condition.json",
    "device": "device.json",
    "diagnosticreport": "diagnosticreport.json",
    "documentreference": "documentreference.json",
    "encounter": "encounter.json",
    "goal": "goal.json",
    "immunization": "immunization.json",
    "location": "location.json",
    "medicationrequest": "medicationrequest.json",
    "observation": "observation.json",
    "organization": "organization.json",
    "patient": "patient.json",
    "practitioner": "practitioner.json",
    "procedure": "procedure.json",
    "provenance": "provenance.json"
};
