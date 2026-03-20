import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import ms, { type StringValue } from "ms";
import { config } from "../config";
import { PrismaClient } from "../generated/client";
import { prisma as defaultPrisma } from "../db/prisma";
import { createAuthModeService, type AuthModeService } from "../auth/authMode";
import {
  ACCESS_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_NAME,
  readCookie,
  setAccessTokenCookie,
  setAuthCookies,
} from "../auth/cookies";
import { getTokenLookupCandidates, hashTokenForStorage } from "../auth/tokenSecurity";

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        username?: string | null;
        email: string;
        name: string;
        role: string;
        mustResetPassword?: boolean;
        impersonatorId?: string;
      };
      principal?: {
        kind: "user";
        userId: string;
      };
    }
  }
}

interface JwtPayload {
  userId: string;
  email: string;
  type: "access" | "refresh";
  impersonatorId?: string;
}

const isJwtPayload = (decoded: unknown): decoded is JwtPayload => {
  if (typeof decoded !== "object" || decoded === null) {
    return false;
  }
  const payload = decoded as Record<string, unknown>;
  const impersonatorOk =
    typeof payload.impersonatorId === "undefined" || typeof payload.impersonatorId === "string";
  return (
    typeof payload.userId === "string" &&
    typeof payload.email === "string" &&
    (payload.type === "access" || payload.type === "refresh") &&
    impersonatorOk
  );
};

const extractToken = (
  req: Request
): { token: string | null; source: "authorization" | "cookie" | null } => {
  const authHeader = req.headers.authorization;
  if (authHeader && typeof authHeader === "string") {
    const parts = authHeader.split(" ");
    if (parts.length === 2 && parts[0] === "Bearer") {
      return { token: parts[1] || null, source: "authorization" };
    }
  }

  return {
    token: readCookie(req, ACCESS_TOKEN_COOKIE_NAME),
    source: "cookie",
  };
};

const verifyToken = (token: string): JwtPayload | null => {
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    if (!isJwtPayload(decoded)) {
      return null;
    }
    if (decoded.type !== "access") {
      return null; // Only accept access tokens in middleware
    }
    return decoded;
  } catch {
    return null;
  }
};

const rotateAccessTokenFromRefreshCookie = async (
  req: Request,
  res: Response,
  prisma: PrismaClient
): Promise<JwtPayload | null> => {
  const refreshToken = readCookie(req, REFRESH_TOKEN_COOKIE_NAME);
  if (!refreshToken) {
    return null;
  }

  let decoded: JwtPayload;
  try {
    const verified = jwt.verify(refreshToken, config.jwtSecret);
    if (!isJwtPayload(verified) || verified.type !== "refresh") {
      return null;
    }
    decoded = verified;
  } catch {
    return null;
  }

  if (config.enableRefreshTokenRotation) {
    const parsedRefreshTtlMs = ms(config.jwtRefreshExpiresIn as StringValue);
    const refreshTtlMs =
      typeof parsedRefreshTtlMs === "number" && parsedRefreshTtlMs > 0
        ? parsedRefreshTtlMs
        : 7 * 24 * 60 * 60 * 1000;
    const expiresAt = new Date(Date.now() + refreshTtlMs);
    const accessSignOptions = {
      expiresIn: config.jwtAccessExpiresIn as StringValue,
      jwtid: crypto.randomUUID(),
    };
    const accessToken = jwt.sign(
      {
        userId: decoded.userId,
        email: decoded.email,
        type: "access",
        impersonatorId: decoded.impersonatorId,
      },
      config.jwtSecret,
      accessSignOptions
    );

    const refreshSignOptions = {
      expiresIn: config.jwtRefreshExpiresIn as StringValue,
      jwtid: crypto.randomUUID(),
    };
    const newRefreshToken = jwt.sign(
      {
        userId: decoded.userId,
        email: decoded.email,
        type: "refresh",
        impersonatorId: decoded.impersonatorId,
      },
      config.jwtSecret,
      refreshSignOptions
    );

    try {
      await prisma.$transaction(async (tx) => {
        const storedToken = await tx.refreshToken.findFirst({
          where: {
            OR: getTokenLookupCandidates(refreshToken).map((candidate) => ({ token: candidate })),
          },
        });

        if (!storedToken || storedToken.userId !== decoded.userId || storedToken.revoked) {
          throw new Error("invalid-refresh-token");
        }

        if (new Date() > storedToken.expiresAt) {
          throw new Error("expired-refresh-token");
        }

        const revoked = await tx.refreshToken.updateMany({
          where: { id: storedToken.id, revoked: false },
          data: { revoked: true },
        });
        if (revoked.count !== 1) {
          throw new Error("invalid-refresh-token");
        }

        await tx.refreshToken.create({
          data: {
            userId: decoded.userId,
            token: hashTokenForStorage(newRefreshToken),
            expiresAt,
          },
        });
      });
    } catch {
      return null;
    }

    setAuthCookies(req, res, {
      accessToken,
      refreshToken: newRefreshToken,
    });

    return verifyToken(accessToken);
  }

  const accessToken = jwt.sign(
    {
      userId: decoded.userId,
      email: decoded.email,
      type: "access",
      impersonatorId: decoded.impersonatorId,
    },
    config.jwtSecret,
    { expiresIn: config.jwtAccessExpiresIn as StringValue }
  );

  setAccessTokenCookie(req, res, accessToken);
  return verifyToken(accessToken);
};

const normalizeRequestPath = (req: Request): string => {
  const raw = (req.originalUrl || req.url || "").split("?")[0] || "";
  return raw.replace(/^\/api(?=\/)/, "");
};

const isAllowedWhileMustResetPassword = (req: Request): boolean => {
  const path = normalizeRequestPath(req);

  if (req.method === "GET" && path === "/auth/me") return true;
  if (req.method === "POST" && path === "/auth/change-password") return true;
  if (req.method === "POST" && path === "/auth/must-reset-password") return true;

  return false;
};

export type AuthMiddlewareDeps = {
  prisma: PrismaClient;
  authModeService: AuthModeService;
};

export const createAuthMiddleware = ({
  prisma,
  authModeService,
}: AuthMiddlewareDeps) => {
  const requireAuth = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const authEnabled = await authModeService.getAuthEnabled();
      if (!authEnabled) {
        const user = await authModeService.getBootstrapActingUser();
        req.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          mustResetPassword: user.mustResetPassword,
        };
        return next();
      }
    } catch (error) {
      console.error("Error reading auth mode:", error);
      res.status(500).json({
        error: "Internal server error",
        message: "Failed to read authentication mode",
      });
      return;
    }

    const extractedToken = extractToken(req);
    let payload = extractedToken.token ? verifyToken(extractedToken.token) : null;

    if (!payload && extractedToken.source !== "authorization") {
      payload = await rotateAccessTokenFromRefreshCookie(req, res, prisma);
    }

    if (!payload) {
      res.status(401).json({
        error: "Unauthorized",
        message: extractedToken.token
          ? "Invalid or expired token"
          : "Authentication token required",
      });
      return;
    }

    try {
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: {
          id: true,
          username: true,
          email: true,
          name: true,
          role: true,
          mustResetPassword: true,
          isActive: true,
        },
      });

      if (!user || !user.isActive) {
        res.status(401).json({
          error: "Unauthorized",
          message: "User account not found or inactive",
        });
        return;
      }

      if (user.mustResetPassword && !isAllowedWhileMustResetPassword(req)) {
        res.status(403).json({
          error: "Forbidden",
          code: "MUST_RESET_PASSWORD",
          message: "You must reset your password before using the app",
        });
        return;
      }

      req.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
        role: user.role,
        mustResetPassword: user.mustResetPassword,
        impersonatorId: payload.impersonatorId,
      };

      next();
    } catch (error) {
      console.error("Error verifying user:", error);
      res.status(500).json({
        error: "Internal server error",
        message: "Failed to verify user",
      });
    }
  };

  const optionalAuth = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const authEnabled = await authModeService.getAuthEnabled();
      if (!authEnabled) {
        // Keep optionalAuth behavior consistent with requireAuth when auth is disabled:
        // attach the bootstrap acting user so downstream routes can authorize ownership correctly.
        const user = await authModeService.getBootstrapActingUser();
        req.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          mustResetPassword: user.mustResetPassword,
        };
        return next();
      }
    } catch (error) {
      console.error("Error reading auth mode:", error);
      return next();
    }

    const extractedToken = extractToken(req);
    let payload = extractedToken.token ? verifyToken(extractedToken.token) : null;

    if (!payload && extractedToken.source !== "authorization") {
      payload = await rotateAccessTokenFromRefreshCookie(req, res, prisma);
    }

    if (!payload) {
      return next();
    }

    try {
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: {
          id: true,
          username: true,
          email: true,
          name: true,
          role: true,
          mustResetPassword: true,
          isActive: true,
        },
      });

      if (user && user.isActive) {
        req.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          mustResetPassword: user.mustResetPassword,
          impersonatorId: payload.impersonatorId,
        };
      }
    } catch (error) {
      console.error("Error in optional auth:", error);
    }

    next();
  };

  return {
    requireAuth,
    optionalAuth,
  };
};

const defaultAuthModeService = createAuthModeService(defaultPrisma);
const defaultAuthMiddleware = createAuthMiddleware({
  prisma: defaultPrisma,
  authModeService: defaultAuthModeService,
});

export const authModeService = defaultAuthModeService;
export const requireAuth = defaultAuthMiddleware.requireAuth;
export const optionalAuth = defaultAuthMiddleware.optionalAuth;
