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
            iterations: 500000, // High iteration count for security
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

export async function handleSignUp(request, env) {
    let email, password;
    
    // Step 1: Robust JSON Parsing (Prevents $500 crash on bad input)
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

        // Step 4: Insert into D1 (env.dataiot is bound via wrangler.toml)
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
