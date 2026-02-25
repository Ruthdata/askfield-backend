import { OAuth2Client } from "google-auth-library";

export const verifyGoogleToken = async (code) => {
  try {
    // Initialize client INSIDE the function so env vars are loaded
    const client = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      "http://localhost:3001"
    );

    console.log("Client ID:", process.env.GOOGLE_CLIENT_ID); // verify it's loading

    const { tokens } = await client.getToken({
      code,
      redirect_uri: "http://localhost:3001",
    });

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    return {
      email: payload.email,
      given_name: payload.given_name,
      family_name: payload.family_name,
      picture: payload.picture,
      sub: payload.sub,
    };
  } catch (error) {
    console.error("FULL Google error:", JSON.stringify(error, null, 2));
    throw new Error("Failed to verify Google token: " + error.message);
  }
};