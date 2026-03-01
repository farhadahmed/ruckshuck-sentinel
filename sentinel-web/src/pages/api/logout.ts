import type { APIRoute } from 'astro';
import { destroySession } from '../../lib/auth';

export const POST: APIRoute = async ({ cookies }) => {
  try {
    const sessionId = cookies.get('sentinel_session')?.value;
    if (sessionId) {
      destroySession(sessionId);
    }

    cookies.delete('sentinel_session', { path: '/' });

    return new Response(
      JSON.stringify({ success: true, message: 'Logged out' }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (err) {
    console.error('Logout error:', err);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
