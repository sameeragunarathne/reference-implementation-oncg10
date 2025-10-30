import ballerina/http;

listener http:Listener httpDefaultListener = http:getDefaultListener();

service / on httpDefaultListener {
    resource function get [string orgId]/[string path]() returns error|json|http:InternalServerError {
        do {
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

    resource function post [string orgId]/[string path]() returns error|json {
        do {
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

    resource function post [string orgId]/[string path]() returns error|json {
        do {
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

    resource function put [string orgId]/[string path]() returns error|json {
        do {
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

}