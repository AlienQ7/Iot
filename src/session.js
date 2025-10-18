// V 0.0.01

import { SignJWT, jwtVerify } from 'jose';

// The key used to sign the JWT. This must be securely stored as a Worker Secret (e.g., JWT_SECRET).
const textEncoder = new TextEncoder();

// We will use a single Access Token set to expire in 24 hours (1 day).

/**
 * Generates a JSON Web Token (JWT) for a user.
 * * @param {string} email The user's email to include in the token payload.
 * @param {string} JWT_SECRET The secret key used to sign the token.
 * @returns {Promise<string>} The generated signed JWT string.
 */
export async function generateJWT(email, JWT_SECRET) {
    // 1. Prepare the secret key for jose
    const secretKey = textEncoder.encode(JWT_SECRET);
    
    // 2. Define the payload (claims)
    const payload = {
        email: email,
        // The issuer of the token (optional)
        iss: 'IoT_Hub_API', 
        // The audience (who the token is for) (optional)
        aud: 'user',       
    };

    // 3. Create and sign the JWT
    // alg: The encryption algorithm to use (HS256 is HMAC using SHA-256)
    // exp: Sets the expiration time (e.g., '24h' for 24 hours)
    const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime('24h') // 24-hour expiration as requested
        .sign(secretKey);

    return token;
}

/**
 * Verifies a JSON Web Token (JWT) and extracts the payload.
 * * @param {string} token The JWT string to verify.
 * @param {string} JWT_SECRET The secret key used to verify the token.
 * @returns {Promise<{email: string}|null>} The decoded payload (including email) or null if verification fails.
 */
export async function verifyJWT(token, JWT_SECRET) {
    try {
        const secretKey = textEncoder.encode(JWT_SECRET);

        const { payload } = await jwtVerify(token, secretKey, {
            issuer: 'IoT_Hub_API',
            audience: 'user',
        });
        
        // Return only the necessary parts of the payload
        return { email: payload.email }; 
        
    } catch (error) {
        // Log errors like token expiration or invalid signature
        console.error("JWT Verification failed:", error.message);
        return null; // Token is invalid or expired
    }
}
