// V 0.0.01

import { generateJWT } from './session'; // Import the function from our new session.js file

// =================================================================
// PASSWORD HASHING/VERIFICATION FUNCTIONS
// =================================================================

// Function to generate a secure hash for a password using Web Crypto API (required for Workers)
async function hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt
    const passwordBuffer = new TextEncoder().encode(password);

    const key = await crypto.subtle.importKey(
        'raw', 
        passwordBuffer, 
        { name: 'PBKDF2' }, 
        false, 
        ['deriveBits', 'deriveKey']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000, // High iteration count for security (Cloudflare limit)
            hash: 'SHA-256',
        },
        key,
        256 // 256 bits (32 bytes)
    );

    const hashArray = new Uint8Array(derivedBits);
    const combined = new Uint8Array(salt.length + hashArray.length);
    combined.set(salt, 0); // Prepend the salt to the hash
    combined.set(hashArray, salt.length);

    // Convert to Base64 string for storage
    return btoa(String.fromCharCode(...combined));
}

// Function to verify an incoming password against the stored combined hash/salt
async function verifyPassword(password, storedHash) {
    // 1. Decode the Base64 stored hash string back into a byte array
    const combinedBytes = new Uint8Array(atob(storedHash).split('').map(char => char.charCodeAt(0)));
    
    // 2. Separate the salt (first 16 bytes) from the hash (remaining bytes)
    const salt = combinedBytes.slice(0, 16);
    const storedHashOnly = combinedBytes.slice(16);

    const passwordBuffer = new TextEncoder().encode(password);

    const key = await crypto.subtle.importKey(
        'raw', 
        passwordBuffer, 
        { name: 'PBKDF2' }, 
        false, 
        ['deriveBits', 'deriveKey']
    );

    // 3. Re-hash the incoming password using the extracted salt
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000, // MUST use the same iteration count!
            hash: 'SHA-256',
        },
        key,
        256 // 256 bits (32 bytes)
    );
    
    // 4. Compare the newly generated hash with the stored hash
    const incomingHash = new Uint8Array(derivedBits);

    // Use Web Crypto's timing-safe comparison to prevent timing attacks
    return crypto.subtle.timingSafeEqual(incomingHash, storedHashOnly);
}

// =================================================================
// ACCOUNT HANDLERS
// =================================================================

export async function handleSignUp(request, env) {
    let email, password;
    
    // Step 1: Robust JSON Parsing
    try {
        ({ email, password } = await request.json());
    } catch (e) {
        return new Response('Invalid JSON format in request body.', { status: 400 });
    }
    
    try {
        // Step 2: Input Validation
        if (!email || !password) {
            return new Response('Email and password required.', { status: 400 });
        }
        
        // Password Policy Check
        const minLength = 8;
        const hasAlphabet = /[a-zA-Z]/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength || !hasAlphabet || !hasSpecialChar) {
            return new Response('Password must be at least 8 chars and include 1 alphabet/1 special character.', { status: 400 });
        }

        // Step 3: Hash Password
        const password_hash = await hashPassword(password);

        // Step 4: Insert into D1
        const stmt = env.dataiot.prepare(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)"
        ).bind(email, password_hash);

        await stmt.run();

        // Step 5: Success Response
        return new Response(JSON.stringify({ success: true, message: 'User created successfully.' }), {
            status: 201,
            headers: { 'Content-Type': 'application/json' },
        });

    } catch (error) {
        // Handle specific unique constraint error (user already exists)
        if (error.message && error.message.includes('UNIQUE constraint failed')) {
             return new Response('User with this email already exists.', { status: 409 });
        }
        // General error handling
        console.error("Signup error:", error);
        return new Response('Internal Server Error', { status: 500 });
    }
}


export async function handleLogin(request, env) {
    let email, password;
    
    // Step 1: Robust JSON Parsing
    try {
        ({ email, password } = await request.json());
    } catch (e) {
        return new Response('Invalid JSON format in request body.', { status: 400 });
    }

    try {
        // Step 2: Input Validation
        if (!email || !password) {
            return new Response('Email and password required.', { status: 400 });
        }

        // Step 3: Retrieve user from D1
        const { results } = await env.dataiot.prepare(
            "SELECT password_hash FROM users WHERE email = ?"
        ).bind(email).all();

        const user = results[0];

        // Check if user exists
        if (!user) {
            // Use a generic failure message for security (prevents enumeration attacks)
            return new Response(JSON.stringify({ success: false, message: 'Invalid credentials.' }), { status: 401 });
        }

        // Step 4: Verify Password
        const isValid = await verifyPassword(password, user.password_hash);

        if (!isValid) {
            return new Response(JSON.stringify({ success: false, message: 'Invalid credentials.' }), { status: 401 });
        }

        // Step 5: Generate JWT Token (24-hour expiration)
        const token = await generateJWT(email, env.JWT_SECRET);
        
        // Calculate the expiration date (1 day from now)
        const expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString();

        // Step 6: Success Response with Secure HttpOnly Cookie
        return new Response(JSON.stringify({ success: true, message: 'Login successful.', token }), {
            status: 200,
            headers: { 
                'Content-Type': 'application/json',
                // Set the JWT as an HttpOnly, Secure, SameSite=Lax cookie
                'Set-Cookie': `auth_token=${token}; Expires=${expirationDate}; Path=/; HttpOnly; Secure; SameSite=Lax`
            },
        });

    } catch (error) {
        console.error("Login error:", error);
        return new Response('Internal Server Error', { status: 500 });
    }
}
