package cl.tuten.function;

import java.util.*;
import com.microsoft.azure.functions.annotation.*;

import cl.tuten.utils.JWTUtil;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.microsoft.azure.functions.*;;

/**
 * Azure Functions with HTTP Trigger.
 */
public class CheckJWTFunction {
    /**
     * This function listens at endpoint "/api/HttpTrigger-Java". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpTrigger-Java&code={your function key}
     * 2. curl "{your host}/api/HttpTrigger-Java?name=HTTP%20Query&code={your function key}"
     * Function Key is not needed when running locally, it is used to invoke function deployed to Azure.
     * More details: https://aka.ms/functions_authorization_keys
     */
    @FunctionName("Check-JWT")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", 
                        methods = {HttpMethod.GET, HttpMethod.POST}, 
                        authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse query parameter
        String query = request.getQueryParameters().get("name");
        String name = request.getBody().orElse(query);
        System.out.println(request.getHeaders());
        String token = request.getHeaders().get("authorization");
        String secret = "1234567890UltraViolento";
        
        if(token == null) {
        	return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a token in the request header").build();
        } else {
            token = token.replaceFirst("Bearer ", "");
        	try {
        		JWTUtil.verifyToken(token, Algorithm.HMAC256(secret));
        	} catch(JWTVerificationException e) {
        		return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Your Token is invalid "+ e).build();
        	}
        	
        	return request.createResponseBuilder(HttpStatus.OK).body("Hello, your token "+token+" is valid" ).build();
        }

        /*if (name == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a name on the query string or in the request body").build();
        } else {
            return request.createResponseBuilder(HttpStatus.OK).body("Hello, " + name).build();
        }*/
    }

}
