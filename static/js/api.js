// Thin wrapper around the Flask JSON API. Failures become ApiError, so callers never
// have to deal with raw responses and a failed request cannot break the interface.

export class ApiError extends Error {
  constructor(message, field = null) {
    super(message);
    this.field = field;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError("Could not reach the local server. Check that python app.py is still running.");
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new ApiError("The server sent an unreadable response.");
  }
  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    throw new ApiError(error.message || "The request failed.", error.field || null);
  }
  return body;
}

function post(path, payload) {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export const api = {
  encrypt: (payload) => post("/api/encrypt", payload),
  decrypt: (payload) => post("/api/decrypt", payload),
  visualize: (payload) => post("/api/visualize", payload),
  simplifiedRc4: (payload) => post("/api/simplified-rc4", payload),
  examples: () => request("/api/examples"),
};
