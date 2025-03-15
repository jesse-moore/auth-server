import cookieParser from "cookie-parser";
import express, { Request, Response } from "express";
import { ServiceStatus } from "./interfaces.js";
import { AuthenticationService, GetAppConfig } from "./services.js";

const app = express();
app.use(cookieParser());

const port = process.env.PORT || 3010;

(async () => {
  try {
    const config = GetAppConfig();
    await AuthenticationService.initialize(config);
    console.log("Auth service initialized successfully");
  } catch (error) {
    console.error("Error during discovery:", error);
    process.exit(1);
  }
})();

/**
 * GET /login
 * Initiates the login flow by generating PKCE parameters,
 * storing them in cookies, and redirecting the user to Cognito.
 */
app.get("/login", async (req: Request, res: Response): Promise<void> => {
  const loginFlowResponse = await AuthenticationService.initiateLoginFlow(res);
  if (loginFlowResponse.status === ServiceStatus.SUCCESS && loginFlowResponse.data) {
    const state = req.query.state as string | undefined;
    state ? res.cookie("auth_state", encodeURIComponent(state), { httpOnly: true, secure: true, sameSite: "lax" }) : res.clearCookie("auth_state");
    res.redirect(loginFlowResponse.data);
    return;
  }

  res.status(500).send("Error initiating login.");
});

/**
 * GET /
 * Handles the redirect from Cognito, exchanges the code for tokens,
 * stores the tokens in secure cookies, and clears the temporary PKCE cookies.
 */
app.get("/callback", async (req: Request, res: Response): Promise<void> => {
  const state = req.cookies.auth_state ? decodeURIComponent(req.cookies.auth_state) : undefined;
  res.clearCookie("auth_state");
  const tokenExchangeResponse = await AuthenticationService.exchangeCodeForTokens(req, res);
  if (tokenExchangeResponse.status === ServiceStatus.SUCCESS) {    
    state ? res.redirect(state) : res.redirect("/");
    return;
  }
  res.status(tokenExchangeResponse.statusCode).send(tokenExchangeResponse.data || tokenExchangeResponse.message);
});

/**
 * GET /verify
 * A verifies or refreshes expired access token.
 */
app.get("/verify", async (req: Request, res: Response): Promise<void> => {
  const idToken = req.cookies.id_token;
  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;
  const sessionId = req.cookies.session_id;

  if ((!idToken || !accessToken) && !refreshToken) {
    res.status(401).send("Not authenticated.");
    return;
  }

  if (refreshToken && (!idToken || !accessToken)) {
    const refreshTokenResponse = await AuthenticationService.refreshTokenGrant(res, refreshToken, sessionId);
    if (refreshTokenResponse.data) {
      res.header("Authorization", `Bearer ${refreshTokenResponse.data.access_token}`);
    }
    res.status(refreshTokenResponse.statusCode).send(refreshTokenResponse.message);
    return;
  }

  const tokenSet = { id_token: idToken, access_token: accessToken, refresh_token: refreshToken };
  const verifyTokenResponse = await AuthenticationService.verifyToken(res, tokenSet, sessionId);
  if (verifyTokenResponse.data) {
    res.header("Authorization", `Bearer ${verifyTokenResponse.data.access_token}`);
  }
  res.status(verifyTokenResponse.statusCode).send(verifyTokenResponse.message);
});

app.listen(port, () => {
  console.log(`Auth service listening on port ${port}`);
});
