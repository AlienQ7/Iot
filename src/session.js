// V 0.0.01

// We will use native Web Crypto API for signing and verifying JWTs (no external library needed).
const textEncoder = new TextEncoder();
const EXPIRATION_HOURS = 24;

/**
 * Converts a string to a Base64 URL-safe string.
 */
function base64UrlEncode(str) {
    let base64 = btoa(str);
    // Convert to URL-safe characters
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generates a JSON Web Token (JWT) using Web Crypto API.
 * @param {string} email The user's email to include in the token payload.
 * @param {string} JWT_SECRET The secret key used to sign the token.
 * @returns {Promise<string>} The generated signed JWT string.
 */
export async function generateJWT(email, JWT_SECRET) {
    // 1. Prepare the key (must be imported from raw bytes)
    const secretKey = await crypto.subtle.importKey(
        "raw",
        textEncoder.encode(JWT_SECRET),
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"]
    );

    // 2. Define Header and Payload
    const header = {
        alg: 'HS256',
        typ: 'JWT'
    };
    
    const now = Date.now();
    const payload = {
        email: email,
        iss: 'IoT_Hub_API',
        aud: 'user',
        iat: Math.floor(now / 1000), // Issued At
        exp: Math.floor(now / 1000) + (EXPIRATION_HOURS * 60 * 60) // Expiration (24 hours)
    };

    // 3. Encode Header and Payload
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const dataToSign = `${encodedHeader}.${encodedPayload}`;

    // 4. Create Signature
    const signature = await crypto.subtle.sign(
        "HMAC",
        secretKey,
        textEncoder.encode(dataToSign)
    );

    const encodedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));

    // 5. Combine and return the final JWT
    return `${dataToSign}.${encodedSignature}`;
}

/**
 * Verifies a JSON Web Token (JWT) using Web Crypto API.
 * * @param {string} token The JWT string to verify.
 * @param {string} JWT_SECRET The secret key used to verify the token.
 * @returns {Promise<{email: string}|null>} The decoded payload (including email) or null if verification fails.
 */
export async function verifyJWT(token, JWT_SECRET) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        
        const [encodedHeader, encodedPayload, encodedSignature] = parts;
        const dataToVerify = `${encodedHeader}.${encodedPayload}`;

        const secretKey = await crypto.subtle.importKey(
            "raw",
            textEncoder.encode(JWT_SECRET),
            { name: "HMAC", hash: { name: "SHA-256" } },
            false,
            ["verify"]
        );
        
        // Decode the signature part for comparison
        const signatureBytes = new Uint8Array(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => c.charCodeAt(0)));

        const isValid = await crypto.subtle.verify(
            "HMAC",
            secretKey,
            signatureBytes,
            textEncoder.encode(dataToVerify)
        );

        if (isValid) {
            // Decode payload and return email
            const payloadJson = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'));
            const payload = JSON.parse(payloadJson);
            
            // Check expiration time (critical security step!)
            if (payload.exp < Math.floor(Date.now() / 1000)) {
                console.error("JWT Verification failed: Token expired.");
                return null;
            }
            
            return { email: payload.email };
        }
    } catch (error) {
        console.error("JWT Verification failed:", error.message);
        return null;
    }
    return null;
}
