import { NextResponse } from "next/server";

import { requireAdminSession } from "@/lib/auth/admin";
import { logRouteError } from "@/lib/security/logging";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "@/lib/security/route-controls";
import {
  getClientIpAddress,
  getRequestPathname,
  getRequestUserAgent,
} from "@/lib/security/request";
import { getSettings, readStoredSettings } from "@/lib/settings";
import {
  setTwoFactorRequirement,
  SignInSecurityError,
} from "@/lib/sign-in-security";

const noStore = { "cache-control": "private, no-store" };

// Turns the two-step sign-in requirement on or off. Administrators only.
export async function PUT(request: Request) {
  const sessionResult = await requireAdminSession(request);

  if (sessionResult instanceof Response) {
    return sessionResult;
  }

  const session = sessionResult;
  const rateLimitResponse = await applyRateLimit({
    category: "sign_in_security_change",
    key: buildRateLimitKey(["sign-in-security", session.user.id]),
    limit: 20,
    request,
    userId: session.user.id,
    windowMs: 10 * 60 * 1000,
  });

  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const body = (await request.json().catch(() => null)) as {
    requireTwoFactor?: unknown;
  } | null;

  if (typeof body?.requireTwoFactor !== "boolean") {
    return NextResponse.json(
      { error: "Say whether two-step sign-in should be required." },
      { headers: noStore, status: 400 },
    );
  }

  if ((await getSettings()).hosted) {
    return NextResponse.json(
      { error: "This setting is for self-hosted installs." },
      { headers: noStore, status: 400 },
    );
  }

  try {
    await setTwoFactorRequirement(
      {
        email: session.user.email,
        ipAddress: getClientIpAddress(request.headers),
        userAgent: getRequestUserAgent(request.headers),
        userId: session.user.id,
      },
      body.requireTwoFactor,
    );

    return NextResponse.json(
      {
        requireTwoFactor:
          (await readStoredSettings())?.requireTwoFactor ?? false,
      },
      { headers: noStore },
    );
  } catch (error) {
    if (error instanceof SignInSecurityError) {
      return NextResponse.json(
        { error: error.message },
        { headers: noStore, status: error.statusCode },
      );
    }

    logRouteError(error, {
      category: "sign_in_security_failure",
      ipAddress: getClientIpAddress(request.headers),
      message: "Unexpected failure while changing sign-in security.",
      path: getRequestPathname(request),
      userId: session.user.id,
    });

    return NextResponse.json(
      { error: "That change could not be saved." },
      { headers: noStore, status: 500 },
    );
  }
}
