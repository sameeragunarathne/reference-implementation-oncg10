import ballerina/http;

listener http:Listener httpDefaultListener = http:getDefaultListener();

service http:InterceptableService / on httpDefaultListener {
    
    public function createInterceptors() returns JwtValidationInterceptor {
        return new JwtValidationInterceptor();
    }

    isolated resource function get [string orgId]/[string path](http:RequestContext requestContext) 
            returns error|json|http:InternalServerError {
        do {
            // Get the validated org_id from request context
            any|error contextValue = requestContext.get(key = "requestContext");
            
            if contextValue is error {
                return <http:InternalServerError>{
                    body: "Request context not found"
                };
            }

            RequestContext|error context = contextValue.ensureType(t = RequestContext);
            
            if context is error {
                return <http:InternalServerError>{
                    body: "Invalid request context type"
                };
            }

            // Use the validated org_id from JWT instead of path parameter
            string validatedOrgId = context.orgId;
            
            // Your business logic here using validatedOrgId
            
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

    isolated resource function post [string orgId]/[string path](http:RequestContext requestContext) 
            returns error|json {
        do {
            // Get the validated org_id from request context
            any|error contextValue = requestContext.get(key = "requestContext");
            
            if contextValue is error {
                return error("Request context not found");
            }

            RequestContext|error context = contextValue.ensureType(t = RequestContext);
            
            if context is error {
                return error("Invalid request context type");
            }

            // Use the validated org_id from JWT instead of path parameter
            string validatedOrgId = context.orgId;
            
            // Your business logic here using validatedOrgId
            
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }

    isolated resource function put [string orgId]/[string path](http:RequestContext requestContext) 
            returns error|json {
        do {
            // Get the validated org_id from request context
            any|error contextValue = requestContext.get(key = "requestContext");
            
            if contextValue is error {
                return error("Request context not found");
            }

            RequestContext|error context = contextValue.ensureType(t = RequestContext);
            
            if context is error {
                return error("Invalid request context type");
            }

            // Use the validated org_id from JWT instead of path parameter
            string validatedOrgId = context.orgId;
            
            // Your business logic here using validatedOrgId
            
        } on fail error err {
            // handle error
            return error("unhandled error", err);
        }
    }
}