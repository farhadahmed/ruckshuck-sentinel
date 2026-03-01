import type { APIRoute } from 'astro';
import { getSession } from '../../lib/auth';

export const POST: APIRoute = async ({ request, cookies }) => {
  try {
    // Verify session
    const sessionId = cookies.get('sentinel_session')?.value;
    if (!sessionId) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const user = getSession(sessionId);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Session expired' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Parse and validate request body
    const body = await request.json();
    const { service_account_json, delegated_admin_email, start_date, end_date } = body;

    if (!service_account_json || !delegated_admin_email || !start_date) {
      return new Response(
        JSON.stringify({ error: 'service_account_json, delegated_admin_email, and start_date are required' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Forward to sentinel-access-context-api
    const backendPayload = {
      service_account_json,
      delegated_admin_email,
      start_date,
      ...(end_date && { end_date }),
    };

    const backendResponse = await fetch('http://localhost:8000/access-context/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(backendPayload),
    });

    const backendData = await backendResponse.json();

    if (!backendResponse.ok) {
      return new Response(JSON.stringify(backendData), {
        status: backendResponse.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify(backendData), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.error('Access context proxy error:', err);
    return new Response(
      JSON.stringify({ error: 'Failed to reach access context service' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
};
