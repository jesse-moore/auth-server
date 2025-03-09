export interface AppConfig {
  clientId: string;
  clientSecret: string;
  userPoolId: string;
  region: string;
  redirect_uri: string;
}

export interface ServiceResponse<T> {
  message: string;
  status: ServiceStatus;
  statusCode: number;
  data?: T | undefined;
}

export enum ServiceStatus {
  SUCCESS,
  TOKEN_EXPIRED,
  TOKEN_INVALID,
  TOKEN_REFRESHED,
  SERVER_ERROR,
  BAD_REQUEST,
  UNAUTHORIZED,
}

export interface TokenSet {
  id_token: string | undefined;
  access_token: string;
  refresh_token: string | undefined;
}

export interface TokenData {
  userId: string;
  expiresAt: number;
}

export interface SessionData extends TokenSet {
  user_id: string;
}

export interface UserData {
  userId: string;
}
