import { handleSignUp } from './auth';

// Main worker handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path.startsWith('/api/user/')) {
      return handleUserApi(path, method, request, env);
    } 
    
    // Default response for the root
    return new Response('Welcome to IoT Hub API. Try POSTing to /api/user/signup', { status: 200 });
  },
};

// User API Router
async function handleUserApi(path, method, request, env) {
  switch (path) {
    case '/api/user/signup':
      if (method === 'POST') {
        // Forward request to the handler defined in auth.js
        return handleSignUp(request, env); 
      }
      break;
      
    case '/api/user/login':
      // This endpoint is reserved for future implementation
      return new Response('Login endpoint not implemented', { status: 501 });
      
    default:
      return new Response('User API Not Found', { status: 404 });
  }
  
  // Method Not Allowed
  return new Response('Method Not Allowed', { status: 405 });
}
