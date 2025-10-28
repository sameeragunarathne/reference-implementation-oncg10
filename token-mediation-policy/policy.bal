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
import ballerina/log;
import choreo/mediation;

@mediation:RequestFlow
public function policyNameIn(mediation:Context ctx, http:Request req) 
                                returns http:Response|false|error|() {
    return ();
}

@mediation:ResponseFlow
public function policyNameOut(mediation:Context ctx, http:Request req, http:Response res) 
                                returns http:Response|false|error|() {
    log:printDebug("Modifying response payload in policyNameOut mediation policy");
    map<json> payload = check res.getJsonPayload().ensureType();
    payload["smart_style_url"] = "https://api.jsonbin.io/v3/qs/68f9f197ae596e708f25eeaa";
    payload["need_patient_banner"] = false;
    payload["patient"] = "1";
    res.setJsonPayload(payload);
    return res;
}

@mediation:FaultFlow
public function policyNameFault(mediation:Context ctx, http:Request req, http:Response? res, http:Response errFlowRes, 
                                    error e) returns http:Response|false|error|() {
    return ();
}
