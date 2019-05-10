package cl.tuten.utils;

import java.util.Enumeration;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;


public final class JWTUtil {
	private static final Log log = LogFactory.getLog(JWTUtil.class);
    private JWT jwt;
    private String token;

    public JWTUtil () { }

    /*public static JWTUtil create(final String token) {
        final JWTUtil verifier = new JWTUtil();
        verifier.token = token;
        
        try {
            verifier.jwt. = (JWT) JWT.decode(token);
            if(verifier.jwt)
            
            if (verifier.jwt.getClaim("uid").isNull()) {
                return null;
            }
            if (verifier.jwt.getClaim("url").isNull()) {
                return null;
            }
            if (verifier.jwt.getClaim("name").isNull()) {
                return null;
            }
            if (verifier.jwt.getClaim("roles").isNull()) {
                return null;
            }
            if (verifier.jwt.getExpiresAt() == null) {
                return null;
            }
            if (verifier.jwt.getIssuedAt() == null) {
                return null;
            }
        } catch (JWTDecodeException exception) {
        	log.error("Error decoding token: " + token, exception);
            return null;
        }
        return verifier;
    }*/


    public static void verifyToken(final String token, final Algorithm algorithm) throws JWTVerificationException {
        final JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(token);
    }

    
}
