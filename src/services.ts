import { CognitoJwtVerifier } from "aws-jwt-verify";
import { JwtExpiredError } from "aws-jwt-verify/error";
import { randomUUID, UUID } from "crypto";
import { CookieOptions, Request, Response } from "express";
import { jwtDecode, JwtPayload } from "jwt-decode";
import cron from "node-cron";
//@ts-ignore
import * as openid from "openid-client";
import { AppConfig, ServiceResponse, ServiceStatus, SessionData, TokenData, TokenSet, UserData } from "./interfaces.js";

class SessionManager {
  private sessions: Map<string, SessionData> = new Map();
  private scheduledTask: cron.ScheduledTask;

  constructor() {
    this.scheduledTask = cron.schedule("0 0 * * *", () => {
      this.purgeExpiredSessions();
    });
  }

  addSession(sessionId: string, tokenSet: SessionData): void {
    this.sessions.set(sessionId, tokenSet);
  }

  getSession(sessionId: string): SessionData | undefined {
    return this.sessions.get(sessionId);
  }

  removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  purgeExpiredSessions(): void {
    const now = Math.floor(Date.now() / 1000); // current time in seconds
    for (const [sessionId, sessionData] of this.sessions.entries()) {
      try {
        const decoded: JwtPayload = jwtDecode(sessionData.access_token);
        if (decoded.exp && now >= decoded.exp) {
          this.sessions.delete(sessionId);
        }
      } catch (error) {
        this.sessions.delete(sessionId);
      }
    }
  }
}

export class AuthenticationService {
  private static config: AppConfig;
  private static openId: openid.Configuration;
  private static sessionManager = new SessionManager();

  static get serverURL(): URL {
    const { region, userPoolId } = AuthenticationService.config;
    return new URL(`https://cognito-idp.${region}.amazonaws.com/${userPoolId}`);
  }

  static async initialize(config: AppConfig): Promise<void> {
    this.config = config;
    const { clientId, clientSecret } = config;
    this.openId = await openid.discovery(this.serverURL, clientId, clientSecret);
  }

  static async initiateLoginFlow(res: Response): Promise<ServiceResponse<string>> {
    const { redirect_uri } = AuthenticationService.config;
    try {
      const code_challenge_method = "S256";

      const code_verifier = openid.randomPKCECodeVerifier();
      const code_challenge = await openid.calculatePKCECodeChallenge(code_verifier);
      let nonce;

      const parameters: Record<string, string> = {
        redirect_uri,
        scope: "openid email",
        code_challenge,
        code_challenge_method,
        nonce: "",
      };

      if (!this.openId.serverMetadata().supportsPKCE()) {
        nonce = openid.randomNonce();
        parameters.nonce = nonce;
      }

      const authUrl = openid.buildAuthorizationUrl(this.openId, parameters);

      res.cookie("pkce_code_verifier", code_verifier, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 10 * 60 * 1000, // 10 minutes
      });
      if (nonce) {
        res.cookie("nonce", nonce, {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          maxAge: 10 * 60 * 1000, // 10 minutes
        });
      }
      return { message: "Redirecting to login", status: ServiceStatus.SUCCESS, data: authUrl.href, statusCode: 200 };
    } catch (error) {
      console.error("Error in /login:", error);
      return { message: "Error initiating login", status: ServiceStatus.SERVER_ERROR, statusCode: 500 };
    }
  }

  static async exchangeCodeForTokens(req: Request, res: Response): Promise<ServiceResponse<UserData>> {
    try {
      const fullUrl = new URL(req.protocol + "://" + req.get("host") + req.originalUrl);

      const code_verifier = req.cookies.pkce_code_verifier;
      const nonce = req.cookies.nonce;

      if (!code_verifier) {
        return { message: "Missing PKCE code verifier.", status: ServiceStatus.BAD_REQUEST, statusCode: 400 };
      }

      const { access_token, id_token, refresh_token } = await openid.authorizationCodeGrant(this.openId, fullUrl, {
        pkceCodeVerifier: code_verifier,
        expectedNonce: nonce,
        idTokenExpected: true,
      });

      const accessTokenData = this.getTokenData(access_token);
      if (!accessTokenData) {
        throw new Error("Error occurred verifying access token data.");
      }

      const tokenSet: TokenSet = { access_token, id_token, refresh_token };
      const sessionId = this.updateSession(tokenSet);
      this.updateCookies(res, tokenSet, sessionId);
      res.clearCookie("pkce_code_verifier");
      res.clearCookie("nonce");

      return {
        message: "Token exchange successful",
        status: ServiceStatus.SUCCESS,
        data: { userId: accessTokenData.userId },
        statusCode: 200,
      };
    } catch (error) {
      console.error("Error in /callback:", error);
      return { message: "Error during token exchange", status: ServiceStatus.SERVER_ERROR, statusCode: 500 };
    }
  }

  static async verifyToken(res: Response, tokenSet: TokenSet, sessionId: UUID): Promise<ServiceResponse<TokenSet>> {
    if (!tokenSet?.access_token) {
      return { message: "No token found", status: ServiceStatus.TOKEN_INVALID, statusCode: 401 };
    }
    try {
      const accessTokenData = this.getTokenData(tokenSet.access_token);
      if ((accessTokenData.expiresAt || 0) < Date.now() / 1000) {
        return await this.refreshTokenGrant(res, tokenSet.refresh_token, sessionId);
      }

      const session = this.sessionManager.getSession(sessionId);
      if (session && session.access_token === tokenSet.access_token) {
        return {
          message: "Token verified",
          status: ServiceStatus.SUCCESS,
          data: tokenSet,
          statusCode: 200,
        };
      }

      await this.verifyTokenWithCognito(tokenSet.access_token);

      return {
        message: "Token verified",
        status: ServiceStatus.SUCCESS,
        data: tokenSet,
        statusCode: 200,
      };
    } catch (error) {
      if (error instanceof JwtExpiredError) {
        return await this.refreshTokenGrant(res, tokenSet.refresh_token, sessionId);
      }

      this.clearCookies(res);
      return { message: "Error during token verification", status: ServiceStatus.TOKEN_INVALID, statusCode: 401 };
    }
  }

  static async refreshTokenGrant(
    res: Response,
    refresh_token: string | undefined,
    sessionId: UUID
  ): Promise<ServiceResponse<TokenSet>> {
    if (!refresh_token) {
      return { message: "No refresh token found", status: ServiceStatus.TOKEN_INVALID, statusCode: 401 };
    }
    try {
      const { access_token, id_token } = await openid.refreshTokenGrant(this.openId, refresh_token, {
        scope: "openid email",
      });
      const tokenSet: TokenSet = { access_token, id_token, refresh_token };
      sessionId = this.updateSession(tokenSet, sessionId);
      this.updateCookies(res, tokenSet, sessionId);
      return {
        message: "Token refreshed",
        status: ServiceStatus.TOKEN_REFRESHED,
        data: tokenSet,
        statusCode: 200,
      };
    } catch (error) {
      this.clearCookies(res);
      return {
        message: (error as any)?.message || "Error during token exchange",
        status: ServiceStatus.TOKEN_INVALID,
        statusCode: 401,
      };
    }
  }

  private static async verifyTokenWithCognito(accessToken: string): Promise<void> {
    const verifier = CognitoJwtVerifier.create({
      userPoolId: this.config.userPoolId,
      tokenUse: "access",
      clientId: this.config.clientId,
    });
    await verifier.verify(accessToken);
  }

  private static getTokenData(accessToken: string): TokenData {
    const data = jwtDecode(accessToken);
    if (!("username" in data) || typeof data.username !== "string" || !data.username) throw new Error("Invalid token");
    return { userId: data.username, expiresAt: data.exp || 0 };
  }

  private static updateSession(tokenSet: TokenSet, sessionId: UUID = randomUUID()): UUID {
    const tokenData = this.getTokenData(tokenSet.access_token);
    this.sessionManager.addSession(sessionId, { ...tokenSet, user_id: tokenData.userId });
    return sessionId;
  }

  private static updateCookies(res: Response, tokenSet: TokenSet, sessionId: UUID): void {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    };
    res.cookie("session_id", sessionId, cookieOptions);
    res.cookie("id_token", tokenSet.id_token, cookieOptions);
    res.cookie("access_token", tokenSet.access_token, cookieOptions);
    if (tokenSet.refresh_token) {
      res.cookie("refresh_token", tokenSet.refresh_token, cookieOptions);
    }
  }

  private static clearCookies(res: Response): void {
    res.clearCookie("id_token");
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    res.clearCookie("session_id");
  }
}

export const GetAppConfig = (): AppConfig => {
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const region = process.env.AWS_REGION;
  const redirect_uri = process.env.REDIRECT_URI;
  if (!clientId || !clientSecret || !userPoolId || !region || !redirect_uri) {
    throw new Error("Missing required environment variables");
  }
  return { clientId, clientSecret, userPoolId, region, redirect_uri };
};
