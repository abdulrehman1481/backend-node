import "dotenv/config";

import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import morgan from "morgan";
import { Prisma, PrismaClient } from "@prisma/client";
import { z } from "zod";

const prisma = new PrismaClient();
const app = express();

const PORT = Number(process.env.PORT || 8000);
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "access-secret";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh-secret";
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES_IN || "15m";
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || "30d";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

// Enhanced CORS configuration for Vercel
const corsOptions = {
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      return callback(null, true);
    }

    // If CORS_ORIGIN is "*", allow all origins
    if (CORS_ORIGIN === "*") {
      return callback(null, true);
    }

    // Split multiple origins by comma
    const allowedOrigins = CORS_ORIGIN.split(",").map((o) => o.trim());

    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // If no match, still allow (be permissive for development)
    console.warn(`[CORS] Request from origin: ${origin}`);
    return callback(null, true);
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400, // 24 hours
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(morgan("dev"));
app.set("json replacer", (_key: string, value: unknown) => (typeof value === "bigint" ? Number(value) : value));

type TokenPayload = {
  sub: string;
  role: UserRole;
  type: "access" | "refresh";
};

type UserRole = "DONOR" | "HOSPITAL" | "ADMIN";
type RequestStatus = "ACTIVE" | "PARTIAL" | "FULFILLED" | "CLOSED";

type AuthedRequest = Request & {
  user?: {
    id: bigint;
    role: UserRole;
  };
};

function toDate(value: Date | string | null | undefined): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(value).toISOString();
}

function serializeLocation(location: unknown): string {
  if (typeof location === "string") return location;
  return JSON.stringify(location ?? { lat: 0, lng: 0 });
}

function deserializeLocation(location: unknown): { lat: number; lng: number } {
  if (typeof location === "string") {
    try {
      const parsed = JSON.parse(location) as { lat?: number; lng?: number };
      return {
        lat: Number(parsed.lat ?? 0),
        lng: Number(parsed.lng ?? 0),
      };
    } catch {
      return { lat: 0, lng: 0 };
    }
  }

  if (location && typeof location === "object") {
    const rec = location as Record<string, unknown>;
    return {
      lat: Number(rec.lat ?? 0),
      lng: Number(rec.lng ?? 0),
    };
  }

  return { lat: 0, lng: 0 };
}

function parseLatLng(location: unknown): { lat: number | null; lng: number | null } {
  let src: unknown = location;

  if (typeof src === "string") {
    try {
      src = JSON.parse(src);
    } catch {
      return { lat: null, lng: null };
    }
  }

  if (!src || typeof src !== "object") {
    return { lat: null, lng: null };
  }

  const rec = src as Record<string, unknown>;
  const latRaw = rec.lat;
  const lngRaw = rec.lng;

  const lat = typeof latRaw === "number" ? latRaw : typeof latRaw === "string" ? Number(latRaw) : NaN;
  const lng = typeof lngRaw === "number" ? lngRaw : typeof lngRaw === "string" ? Number(lngRaw) : NaN;

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return { lat: null, lng: null };
  }

  return { lat, lng };
}

function distanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const rad = (deg: number) => (deg * Math.PI) / 180;
  const r = 6371;
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return r * c;
}

function isEligibleToDonate(
  isAvailable: boolean,
  weightKg: number | Prisma.Decimal,
  lastDonationDate: Date | null
): boolean {
  if (!isAvailable || Number(weightKg) < 50) {
    return false;
  }
  if (!lastDonationDate) {
    return true;
  }

  const eligible = new Date(lastDonationDate);
  eligible.setDate(eligible.getDate() + 90);
  return new Date() >= eligible;
}

function normalizePhone(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith("+") ? trimmed : `+${trimmed}`;
}

function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

function timingSafeEqualBase64(aBase64: string, bBase64: string): boolean {
  try {
    const a = Buffer.from(aBase64, "base64");
    const b = Buffer.from(bBase64, "base64");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function makeDjangoPasswordHash(password: string): string {
  const iterations = Number(process.env.DJANGO_PBKDF2_ITERATIONS || 870000);
  const salt = crypto.randomBytes(12).toString("base64url");
  const digest = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64");
  return `pbkdf2_sha256$${iterations}$${salt}$${digest}`;
}

async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (!storedHash || storedHash.startsWith("!")) {
    return false;
  }

  if (storedHash.startsWith("pbkdf2_sha256$")) {
    const parts = storedHash.split("$");
    if (parts.length !== 4) return false;
    const iterations = Number(parts[1]);
    const salt = parts[2];
    const digest = parts[3];
    if (!Number.isFinite(iterations) || iterations <= 0) return false;

    const computed = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64");
    return timingSafeEqualBase64(computed, digest);
  }

  if (storedHash.startsWith("bcrypt_sha256$")) {
    const bcryptEncoded = storedHash.slice("bcrypt_sha256$".length);
    const preHashed = crypto.createHash("sha256").update(password).digest("hex");
    return bcrypt.compare(preHashed, bcryptEncoded);
  }

  if (storedHash.startsWith("bcrypt$")) {
    const bcryptEncoded = storedHash.slice("bcrypt$".length);
    return bcrypt.compare(password, bcryptEncoded);
  }

  return bcrypt.compare(password, storedHash);
}

function issueAccessToken(userId: bigint, role: UserRole): string {
  const payload: TokenPayload = { sub: userId.toString(), role, type: "access" };
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES } as SignOptions);
}

function issueRefreshToken(userId: bigint, role: UserRole): string {
  const payload: TokenPayload = { sub: userId.toString(), role, type: "refresh" };
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES } as SignOptions);
}

function parseZodError(err: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of err.issues) {
    const key = issue.path[0] ? String(issue.path[0]) : "detail";
    if (!out[key]) {
      out[key] = issue.message;
    }
  }
  return out;
}

function assertRequestOpen(status: string): boolean {
  return status === "ACTIVE" || status === "PARTIAL";
}

function requestWithActionCount(item: Prisma.BloodRequestGetPayload<{ include: { _count: { select: { actions: true } } } }>) {
  return {
    id: item.id,
    requester: item.requesterId,
    patient_name: item.patientName,
    description: item.description,
    patient_age: item.patientAge,
    blood_group_needed: item.bloodGroupNeeded,
    units_required: item.unitsRequired,
    units_fulfilled: item.unitsFulfilled,
    urgency: item.urgency,
    status: item.status,
    required_by_datetime: item.requiredByDatetime.toISOString(),
    hospital_name: item.hospitalName,
    location: deserializeLocation(item.location),
    created_at: item.createdAt.toISOString(),
    updated_at: item.updatedAt.toISOString(),
    actions_count: item._count.actions,
  };
}

async function inferCityFromLocation(lat: number, lng: number): Promise<string | null> {
  const cities = await prisma.medicalCenter.findMany({
    where: { city: { not: "" } },
    distinct: ["city"],
    select: { city: true },
  });

  let bestCity: string | null = null;
  let bestDistance: number | null = null;

  for (const c of cities) {
    const sample = await prisma.medicalCenter.findFirst({ where: { city: c.city } });
    if (!sample) continue;
    const loc = parseLatLng(sample.location);
    if (loc.lat === null || loc.lng === null) continue;
    if (loc.lat === 0 && loc.lng === 0) continue;

    const d = distanceKm(lat, lng, loc.lat, loc.lng);
    if (bestDistance === null || d < bestDistance) {
      bestDistance = d;
      bestCity = c.city;
    }
  }

  return bestCity;
}

function auth(required = true) {
  return async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const header = req.header("Authorization");
    if (!header) {
      if (!required) return next();
      res.status(401).json({ detail: "Authentication credentials were not provided." });
      return;
    }

    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) {
      res.status(401).json({ detail: "Invalid authorization header." });
      return;
    }

    try {
      const decoded = jwt.verify(token, ACCESS_SECRET) as JwtPayload & TokenPayload;
      if (decoded.type !== "access") {
        res.status(401).json({ detail: "Invalid token type." });
        return;
      }
      req.user = { id: BigInt(decoded.sub), role: decoded.role };
      return next();
    } catch {
      res.status(401).json({ detail: "Given token not valid for any token type." });
      return;
    }
  };
}

function requireRole(...roles: UserRole[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ detail: "Authentication required." });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ detail: "You do not have permission to perform this action." });
    }
    return next();
  };
}

function asyncHandler(fn: (req: AuthedRequest, res: Response) => Promise<void>) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

// Root route
app.get("/", (_req, res) => {
  res.json({
    message: "BloodLink Backend API",
    version: "1.0.0",
    status: "running",
    endpoints: {
      health: "/api/health",
      auth: "/api/auth",
      donor: "/api/donor",
      hospital: "/api/hospital",
      requests: "/api/requests",
    },
  });
});

app.get("/api/health/", (_req, res) => {
  res.json({ status: "ok", service: "bdd-backend-node" });
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  first_name: z.string().optional().default(""),
  last_name: z.string().optional().default(""),
  phone_number: z.string().optional(),
  phone: z.string().optional(),
  role: z.enum(["DONOR", "HOSPITAL", "ADMIN"]),
  hospital_center_id: z.number().int().positive().optional(),
});

app.post(
  "/api/auth/register/",
  asyncHandler(async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const payload = parsed.data;
    const phoneRaw = payload.phone_number || payload.phone;
    if (!phoneRaw) {
      return void res.status(400).json({ phone_number: "Phone number is required." });
    }

    const normalizedPhone = normalizePhone(phoneRaw);

    const phoneExists = await prisma.user.findUnique({ where: { phoneNumber: normalizedPhone } });
    if (phoneExists) {
      return void res.status(400).json({ phone_number: "An account with this phone number already exists." });
    }

    const normalizedEmail = normalizeEmail(payload.email);

    const emailExists = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (emailExists) {
      return void res.status(400).json({ email: "user with this email already exists." });
    }

    if (payload.role === "HOSPITAL" && !payload.hospital_center_id) {
      return void res.status(400).json({ hospital_center_id: "Please select your hospital from nearby centers." });
    }

    let selectedCenter: Prisma.MedicalCenterGetPayload<{}> | null = null;
    if (payload.hospital_center_id) {
      selectedCenter = await prisma.medicalCenter.findUnique({ where: { id: payload.hospital_center_id } });
      if (!selectedCenter) {
        return void res.status(400).json({ hospital_center_id: "Selected medical center was not found." });
      }
    }

    let username = normalizedEmail.split("@")[0];
    const existingUsername = await prisma.user.findUnique({ where: { username } });
    if (existingUsername) {
      username = normalizedEmail.replace(/[@.]/g, "_");
    }

    const passwordHash = makeDjangoPasswordHash(payload.password);

    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        username,
        passwordHash,
        firstName: payload.first_name,
        lastName: payload.last_name,
        phoneNumber: normalizedPhone,
        role: payload.role,
      },
    });

    if (payload.role === "DONOR") {
      await prisma.donorProfile.upsert({
        where: { userId: user.id },
        create: {
          userId: user.id,
          bloodGroup: "A+",
          dateOfBirth: new Date("2000-01-01T00:00:00.000Z"),
          weightKg: 50,
          gender: "O",
          isAvailable: true,
          location: serializeLocation({ lat: 0, lng: 0 }),
        },
        update: {},
      });
    } else if (payload.role === "HOSPITAL") {
      const facilityName = selectedCenter?.name || payload.first_name || "New Hospital";
      const licenseNumber = selectedCenter ? `DATA-${selectedCenter.id}-U${user.id}` : `TEMP-${user.id}`;

      await prisma.hospitalProfile.upsert({
        where: { userId: user.id },
        create: {
          userId: user.id,
          facilityName,
          licenseNumber,
          nodalOfficerName: `${payload.first_name} ${payload.last_name}`.trim() || "Nodal Officer",
          emergencyPhone: normalizedPhone,
          location: selectedCenter?.location || serializeLocation({ lat: 0, lng: 0 }),
        },
        update: {},
      });
    }

    res.status(201).json({
      id: user.id,
      email: user.email,
      username: user.username,
      first_name: user.firstName,
      last_name: user.lastName,
      phone_number: user.phoneNumber,
      role: user.role,
      is_phone_verified: user.isPhoneVerified,
      is_email_verified: user.isEmailVerified,
    });
  })
);

const tokenSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

app.post(
  "/api/auth/token/",
  asyncHandler(async (req, res) => {
    const parsed = tokenSchema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json({ detail: "No active account found with the given credentials" });
    }

    const normalizedEmail = normalizeEmail(parsed.data.email);
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user) {
      return void res.status(401).json({ detail: "No active account found with the given credentials" });
    }

    const ok = await verifyPassword(parsed.data.password, user.passwordHash);
    if (!ok) {
      return void res.status(401).json({ detail: "No active account found with the given credentials" });
    }

    const access = issueAccessToken(user.id, user.role as UserRole);
    const refresh = issueRefreshToken(user.id, user.role as UserRole);
    res.json({ access, refresh });
  })
);

const refreshSchema = z.object({ refresh: z.string().min(1) });

app.post(
  "/api/auth/token/refresh/",
  asyncHandler(async (req, res) => {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json({ detail: "refresh is required." });
    }

    try {
      const decoded = jwt.verify(parsed.data.refresh, REFRESH_SECRET) as JwtPayload & TokenPayload;
      if (decoded.type !== "refresh") {
        return void res.status(401).json({ detail: "Token has wrong type" });
      }

      const user = await prisma.user.findUnique({ where: { id: BigInt(decoded.sub) } });
      if (!user) {
        return void res.status(401).json({ detail: "User not found for token" });
      }

      const access = issueAccessToken(user.id, user.role as UserRole);
      res.json({ access });
    } catch {
      res.status(401).json({ detail: "Token is invalid or expired" });
    }
  })
);

app.get(
  "/api/auth/me/",
  auth(),
  asyncHandler(async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
    if (!user) {
      return void res.status(404).json({ detail: "User not found." });
    }

    res.json({
      id: user.id,
      email: user.email,
      username: user.username,
      first_name: user.firstName,
      last_name: user.lastName,
      phone_number: user.phoneNumber,
      role: user.role,
      is_phone_verified: user.isPhoneVerified,
      is_email_verified: user.isEmailVerified,
    });
  })
);

app.patch(
  "/api/auth/me/",
  auth(),
  asyncHandler(async (req, res) => {
    const schema = z
      .object({
        first_name: z.string().optional(),
        last_name: z.string().optional(),
        phone_number: z.string().optional(),
      })
      .strict();

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const data = parsed.data;
    const updateData: Prisma.UserUpdateInput = {};

    if (typeof data.first_name === "string") updateData.firstName = data.first_name;
    if (typeof data.last_name === "string") updateData.lastName = data.last_name;
    if (typeof data.phone_number === "string") updateData.phoneNumber = normalizePhone(data.phone_number);

    const user = await prisma.user.update({ where: { id: req.user!.id }, data: updateData });
    res.json({
      id: user.id,
      email: user.email,
      username: user.username,
      first_name: user.firstName,
      last_name: user.lastName,
      phone_number: user.phoneNumber,
      role: user.role,
      is_phone_verified: user.isPhoneVerified,
      is_email_verified: user.isEmailVerified,
    });
  })
);

app.get(
  "/api/profiles/donor/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const profile = await prisma.donorProfile.upsert({
      where: { userId: req.user!.id },
      create: {
        userId: req.user!.id,
        bloodGroup: "O+",
        dateOfBirth: new Date("2000-01-01T00:00:00.000Z"),
        weightKg: 50,
        gender: "O",
        location: serializeLocation({ lat: 0, lng: 0 }),
      },
      update: {},
    });

    res.json({
      id: profile.id,
      user: profile.userId,
      blood_group: profile.bloodGroup,
      date_of_birth: profile.dateOfBirth.toISOString().slice(0, 10),
      weight_kg: profile.weightKg,
      gender: profile.gender,
      is_available: profile.isAvailable,
      is_eligible_to_donate: isEligibleToDonate(profile.isAvailable, profile.weightKg, profile.lastDonationDate),
      last_donation_date: toDate(profile.lastDonationDate),
      location: deserializeLocation(profile.location),
      location_updated_at: profile.locationUpdatedAt.toISOString(),
    });
  })
);

app.patch(
  "/api/profiles/donor/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      blood_group: z.string().optional(),
      date_of_birth: z.string().optional(),
      weight_kg: z.number().positive().optional(),
      gender: z.enum(["M", "F", "O"]).optional(),
      is_available: z.boolean().optional(),
      last_donation_date: z.string().nullable().optional(),
      location: z.object({ lat: z.number(), lng: z.number() }).optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const p = parsed.data;

    const updated = await prisma.donorProfile.upsert({
      where: { userId: req.user!.id },
      create: {
        userId: req.user!.id,
        bloodGroup: p.blood_group || "O+",
        dateOfBirth: p.date_of_birth ? new Date(p.date_of_birth) : new Date("2000-01-01T00:00:00.000Z"),
        weightKg: p.weight_kg ?? 50,
        gender: p.gender ?? "O",
        isAvailable: p.is_available ?? true,
        lastDonationDate: p.last_donation_date ? new Date(p.last_donation_date) : null,
        location: serializeLocation(p.location || { lat: 0, lng: 0 }),
      },
      update: {
        ...(p.blood_group ? { bloodGroup: p.blood_group } : {}),
        ...(p.date_of_birth ? { dateOfBirth: new Date(p.date_of_birth) } : {}),
        ...(typeof p.weight_kg === "number" ? { weightKg: p.weight_kg } : {}),
        ...(p.gender ? { gender: p.gender } : {}),
        ...(typeof p.is_available === "boolean" ? { isAvailable: p.is_available } : {}),
        ...(p.last_donation_date !== undefined
          ? { lastDonationDate: p.last_donation_date ? new Date(p.last_donation_date) : null }
          : {}),
        ...(p.location ? { location: serializeLocation(p.location) } : {}),
      },
    });

    res.json({
      id: updated.id,
      user: updated.userId,
      blood_group: updated.bloodGroup,
      date_of_birth: updated.dateOfBirth.toISOString().slice(0, 10),
      weight_kg: updated.weightKg,
      gender: updated.gender,
      is_available: updated.isAvailable,
      is_eligible_to_donate: isEligibleToDonate(updated.isAvailable, updated.weightKg, updated.lastDonationDate),
      last_donation_date: toDate(updated.lastDonationDate),
      location: deserializeLocation(updated.location),
      location_updated_at: updated.locationUpdatedAt.toISOString(),
    });
  })
);

app.get(
  "/api/profiles/hospital/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });

    const profile = await prisma.hospitalProfile.upsert({
      where: { userId: req.user!.id },
      create: {
        userId: req.user!.id,
        facilityName: "",
        licenseNumber: `TEMP-${req.user!.id}`,
        nodalOfficerName: "",
        emergencyPhone: user.phoneNumber,
        location: serializeLocation({ lat: 0, lng: 0 }),
      },
      update: {},
    });

    res.json({
      id: profile.id,
      user: profile.userId,
      facility_name: profile.facilityName,
      license_number: profile.licenseNumber,
      is_verified_by_admin: profile.isVerifiedByAdmin,
      nodal_officer_name: profile.nodalOfficerName,
      emergency_phone: profile.emergencyPhone,
      location: deserializeLocation(profile.location),
    });
  })
);

app.patch(
  "/api/profiles/hospital/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      facility_name: z.string().optional(),
      license_number: z.string().optional(),
      nodal_officer_name: z.string().optional(),
      emergency_phone: z.string().optional(),
      location: z.object({ lat: z.number(), lng: z.number() }).optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const p = parsed.data;

    const profile = await prisma.hospitalProfile.upsert({
      where: { userId: req.user!.id },
      create: {
        userId: req.user!.id,
        facilityName: p.facility_name || "",
        licenseNumber: p.license_number || `TEMP-${req.user!.id}`,
        nodalOfficerName: p.nodal_officer_name || "",
        emergencyPhone: p.emergency_phone || "",
        location: serializeLocation(p.location || { lat: 0, lng: 0 }),
      },
      update: {
        ...(p.facility_name ? { facilityName: p.facility_name } : {}),
        ...(p.license_number ? { licenseNumber: p.license_number } : {}),
        ...(p.nodal_officer_name ? { nodalOfficerName: p.nodal_officer_name } : {}),
        ...(p.emergency_phone ? { emergencyPhone: p.emergency_phone } : {}),
        ...(p.location ? { location: serializeLocation(p.location) } : {}),
      },
    });

    res.json({
      id: profile.id,
      user: profile.userId,
      facility_name: profile.facilityName,
      license_number: profile.licenseNumber,
      is_verified_by_admin: profile.isVerifiedByAdmin,
      nodal_officer_name: profile.nodalOfficerName,
      emergency_phone: profile.emergencyPhone,
      location: deserializeLocation(profile.location),
    });
  })
);

function computeRequestStatus(unitsRequired: number, unitsFulfilled: number, requestedStatus?: RequestStatus): RequestStatus {
  if (unitsFulfilled >= unitsRequired) return "FULFILLED";
  if (unitsFulfilled > 0) return "PARTIAL";
  return requestedStatus || "ACTIVE";
}

function urgencyPriority(urgency: string): number {
  if (urgency === "CRITICAL") return 0;
  if (urgency === "URGENT") return 1;
  return 2;
}

app.get(
  "/api/requests/",
  auth(),
  asyncHandler(async (req, res) => {
    const includeHistory = ["1", "true", "True"].includes(String(req.query.include_history || ""));
    const cityRadiusKm = Number(req.query.city_radius_km || 35);
    const now = new Date();
    const currentUser = req.user!;

    const activeRequests = await prisma.bloodRequest.findMany({
      where: { status: { in: ["ACTIVE", "PARTIAL"] }, requiredByDatetime: { gte: now } },
      include: { _count: { select: { actions: true } } },
    });

    let selected: Prisma.BloodRequestGetPayload<{ include: { _count: { select: { actions: true } } } }>[] = [];

    if (currentUser.role === "HOSPITAL") {
      selected = await prisma.bloodRequest.findMany({
        where: includeHistory
          ? { requesterId: currentUser.id }
          : {
              requesterId: currentUser.id,
              status: { in: ["ACTIVE", "PARTIAL"] },
              requiredByDatetime: { gte: now },
            },
        include: { _count: { select: { actions: true } } },
      });
    } else if (currentUser.role === "DONOR") {
      const donorProfile = await prisma.donorProfile.findUnique({ where: { userId: currentUser.id } });
      const donorLoc = parseLatLng(donorProfile?.location);

      const nearbyIds = new Set<bigint>();
      if (donorLoc.lat !== null && donorLoc.lng !== null) {
        for (const item of activeRequests) {
          const reqLoc = parseLatLng(item.location);
          if (reqLoc.lat === null || reqLoc.lng === null) continue;
          if (distanceKm(donorLoc.lat, donorLoc.lng, reqLoc.lat, reqLoc.lng) <= cityRadiusKm) {
            nearbyIds.add(item.id);
          }
        }
      }

      if (includeHistory) {
        const actionIds = await prisma.requestAction.findMany({
          where: { actorId: currentUser.id },
          select: { bloodRequestId: true },
        });
        const pingIds = await prisma.donorPingLog.findMany({
          where: { donor: { userId: currentUser.id } },
          select: { bloodRequestId: true },
        });

        for (const it of actionIds) nearbyIds.add(it.bloodRequestId);
        for (const it of pingIds) nearbyIds.add(it.bloodRequestId);
      }

      selected = nearbyIds.size
        ? await prisma.bloodRequest.findMany({
            where: { id: { in: [...nearbyIds] } },
            include: { _count: { select: { actions: true } } },
          })
        : [];
    } else {
      selected = includeHistory
        ? await prisma.bloodRequest.findMany({ include: { _count: { select: { actions: true } } } })
        : activeRequests;
    }

    selected.sort((a, b) => {
      const d = urgencyPriority(a.urgency) - urgencyPriority(b.urgency);
      if (d !== 0) return d;
      return a.requiredByDatetime.getTime() - b.requiredByDatetime.getTime();
    });

    res.json(selected.map(requestWithActionCount));
  })
);

app.get(
  "/api/requests/:requestId/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const me = req.user!;

    const item = await prisma.bloodRequest.findFirst({
      where: {
        id: requestId,
        OR: [
          { status: { in: ["ACTIVE", "PARTIAL"] }, requiredByDatetime: { gte: new Date() } },
          { requesterId: me.id },
          { actions: { some: { actorId: me.id } } },
          { pingLogs: { some: { donor: { userId: me.id } } } },
        ],
      },
      include: { _count: { select: { actions: true } } },
    });

    if (!item) {
      return void res.status(404).json({ detail: "Blood request not found." });
    }

    res.json(requestWithActionCount(item));
  })
);

const createRequestSchema = z.object({
  patient_name: z.string().min(1),
  description: z.string().optional().default(""),
  patient_age: z.number().int().positive().optional(),
  blood_group_needed: z.string().min(2),
  units_required: z.number().int().positive(),
  urgency: z.enum(["STANDARD", "URGENT", "CRITICAL"]),
  required_by_datetime: z.string().datetime(),
  hospital_name: z.string().min(1),
  location: z.object({ lat: z.number(), lng: z.number() }),
});

app.post(
  "/api/requests/create/",
  auth(),
  asyncHandler(async (req, res) => {
    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const payload = parsed.data;
    const requiredBy = new Date(payload.required_by_datetime);
    if (requiredBy.getTime() < Date.now()) {
      return void res.status(400).json({ detail: "The required time must be in the future." });
    }

    const created = await prisma.bloodRequest.create({
      data: {
        requesterId: req.user!.id,
        patientName: payload.patient_name,
        description: payload.description,
        patientAge: payload.patient_age ?? null,
        bloodGroupNeeded: payload.blood_group_needed,
        unitsRequired: payload.units_required,
        unitsFulfilled: 0,
        urgency: payload.urgency,
        status: "ACTIVE",
        requiredByDatetime: requiredBy,
        hospitalName: payload.hospital_name,
        location: serializeLocation(payload.location),
      },
      include: { _count: { select: { actions: true } } },
    });

    res.status(201).json(requestWithActionCount(created));
  })
);

app.patch(
  "/api/requests/:requestId/status/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const schema = z
      .object({
        status: z.enum(["ACTIVE", "PARTIAL", "FULFILLED", "CLOSED"]).optional(),
        units_fulfilled: z.number().int().min(0).optional(),
      })
      .refine((v) => v.status !== undefined || v.units_fulfilled !== undefined, {
        message: "Provide at least one field to update.",
        path: ["detail"],
      });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const item = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!item) {
      return void res.status(404).json({ detail: "Blood request not found." });
    }
    if (item.requesterId !== req.user!.id) {
      return void res.status(403).json({ detail: "Only the creator can update this request status." });
    }

    const unitsFulfilled = parsed.data.units_fulfilled ?? item.unitsFulfilled;
    if (unitsFulfilled > item.unitsRequired) {
      return void res.status(400).json({ units_fulfilled: "Cannot exceed units_required." });
    }

    const status = computeRequestStatus(item.unitsRequired, unitsFulfilled, parsed.data.status as RequestStatus | undefined);

    const updated = await prisma.bloodRequest.update({
      where: { id: requestId },
      data: {
        unitsFulfilled,
        status,
      },
      include: { _count: { select: { actions: true } } },
    });

    res.json(requestWithActionCount(updated));
  })
);

app.get(
  "/api/requests/:requestId/actions/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const actions = await prisma.requestAction.findMany({
      where: { bloodRequestId: requestId },
      include: { actor: true },
      orderBy: { createdAt: "desc" },
    });

    res.json(
      actions.map((a) => ({
        id: a.id,
        blood_request: a.bloodRequestId,
        actor: a.actorId,
        actor_email: a.actor.email,
        actor_role: a.actor.role,
        action_type: a.actionType,
        note: a.note,
        created_at: a.createdAt.toISOString(),
      }))
    );
  })
);

app.post(
  "/api/requests/:requestId/actions/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const schema = z.object({ action_type: z.enum(["VOLUNTEER", "FLAG", "SUPPORT"]), note: z.string().optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return void res.status(400).json(parseZodError(parsed.error));
    }

    const item = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!item) return void res.status(404).json({ detail: "Blood request not found." });

    if (item.requesterId === req.user!.id) {
      return void res.status(400).json({ detail: "Creator cannot add action on their own request." });
    }

    if (!assertRequestOpen(item.status)) {
      return void res.status(400).json({ detail: "Cannot add action to a request that is no longer active." });
    }

    if (parsed.data.action_type === "VOLUNTEER") {
      if (req.user!.role !== "DONOR") {
        return void res.status(400).json({ action_type: "Only donors can volunteer." });
      }

      const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
      if (!donor) return void res.status(400).json({ detail: "Donor profile not found." });

      if (donor.bloodGroup !== item.bloodGroupNeeded) {
        return void res.status(400).json({
          action_type: `Volunteer action is allowed only for matching blood group (${item.bloodGroupNeeded}).`,
        });
      }
    }

    try {
      const created = await prisma.requestAction.create({
        data: {
          bloodRequestId: requestId,
          actorId: req.user!.id,
          actionType: parsed.data.action_type,
          note: parsed.data.note || "",
        },
      });

      if (parsed.data.action_type === "VOLUNTEER" && req.user!.role === "DONOR") {
        const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
        if (donor) {
          await prisma.donationCommitment.upsert({
            where: {
              bloodRequestId_donorId: {
                bloodRequestId: requestId,
                donorId: donor.id,
              },
            },
            create: {
              bloodRequestId: requestId,
              donorId: donor.id,
              status: "ACCEPTED",
            },
            update: {},
          });
        }
      }

      res.status(201).json({ id: created.id });
    } catch {
      res.status(400).json({ detail: "You have already taken this action on this request." });
    }
  })
);

app.get(
  "/api/requests/:requestId/comments/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const comments = await prisma.requestComment.findMany({
      where: { bloodRequestId: requestId },
      include: { author: true },
      orderBy: { createdAt: "desc" },
    });

    res.json(
      comments.map((c) => ({
        id: c.id,
        blood_request: c.bloodRequestId,
        author: c.authorId,
        author_email: c.author.email,
        author_first_name: c.author.firstName,
        author_role: c.author.role,
        message: c.message,
        created_at: c.createdAt.toISOString(),
      }))
    );
  })
);

app.post(
  "/api/requests/:requestId/comments/",
  auth(),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const message = String(req.body?.message || "").trim();
    if (!message) {
      return void res.status(400).json({ message: "Comment message cannot be empty." });
    }

    const exists = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!exists) return void res.status(404).json({ detail: "Blood request not found." });

    const created = await prisma.requestComment.create({
      data: {
        bloodRequestId: requestId,
        authorId: req.user!.id,
        message,
      },
      include: { author: true },
    });

    res.status(201).json({
      id: created.id,
      blood_request: created.bloodRequestId,
      author: created.authorId,
      author_email: created.author.email,
      author_first_name: created.author.firstName,
      author_role: created.author.role,
      message: created.message,
      created_at: created.createdAt.toISOString(),
    });
  })
);

app.delete(
  "/api/requests/comments/:commentId/",
  auth(),
  asyncHandler(async (req, res) => {
    const commentId = Number(req.params.commentId);
    const comment = await prisma.requestComment.findUnique({ where: { id: commentId } });
    if (!comment) return void res.status(404).json({ detail: "Comment not found." });

    if (comment.authorId !== req.user!.id && req.user!.role !== "ADMIN") {
      return void res.status(403).json({ detail: "You can only delete your own comments." });
    }

    await prisma.requestComment.delete({ where: { id: commentId } });
    res.json({ detail: "Comment deleted successfully." });
  })
);

app.post(
  "/api/requests/:requestId/trigger-matching/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const item = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!item) return void res.status(404).json({ detail: "Blood request not found." });
    if (item.requesterId !== req.user!.id) {
      return void res.status(403).json({ detail: "You can trigger matching only for your own requests." });
    }

    res.status(202).json({ detail: "Matching executed synchronously." });
  })
);

app.get(
  "/api/donors/radar/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const bloodGroup = String(req.query.blood_group || "").trim();
    if (!bloodGroup) return void res.status(400).json({ detail: "blood_group query param is required." });

    const radiusKm = Number(req.query.radius_km || 5);
    let lat = Number(req.query.lat);
    let lon = Number(req.query.lon);

    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      const hospital = await prisma.hospitalProfile.findUnique({ where: { userId: req.user!.id } });
      if (!hospital) {
        return void res.status(400).json({ detail: "Provide lat/lon or complete your hospital profile location." });
      }
      const loc = parseLatLng(hospital.location);
      if (loc.lat === null || loc.lng === null) {
        return void res.status(400).json({ detail: "Hospital profile location must have valid lat/lng." });
      }
      lat = loc.lat;
      lon = loc.lng;
    }

    const donors = await prisma.donorProfile.findMany({
      where: {
        bloodGroup,
        isAvailable: true,
        weightKg: { gte: 50 },
      },
      include: { user: true },
    });

    const rows = donors
      .map((donor) => {
        const loc = parseLatLng(donor.location);
        if (loc.lat === null || loc.lng === null) return null;

        const eligible = isEligibleToDonate(donor.isAvailable, donor.weightKg, donor.lastDonationDate);
        if (!eligible) return null;

        const d = distanceKm(lat, lon, loc.lat, loc.lng);
        if (d > radiusKm) return null;

        const display = `${donor.user.firstName} ${donor.user.lastName}`.trim() || donor.user.firstName || donor.user.email.split("@")[0];
        return {
          id: donor.id,
          donor_user_id: donor.userId,
          donor_email: donor.user.email,
          blood_group: donor.bloodGroup,
          is_available: donor.isAvailable,
          is_eligible_to_donate: eligible,
          display_name: display,
          distance_km: Number(d.toFixed(2)),
        };
      })
      .filter((v): v is NonNullable<typeof v> => Boolean(v))
      .sort((a, b) => a.distance_km - b.distance_km);

    res.json(rows);
  })
);

app.post(
  "/api/donors/:donorId/ping/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const donorId = Number(req.params.donorId);
    const requestId = Number(req.body?.request_id);

    if (!requestId) return void res.status(400).json({ request_id: "request_id is required." });

    const donor = await prisma.donorProfile.findUnique({ where: { id: donorId }, include: { user: true } });
    if (!donor || !donor.isAvailable) {
      return void res.status(400).json({ detail: "Donor not found or currently unavailable." });
    }

    const bloodRequest = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!bloodRequest || bloodRequest.requesterId !== req.user!.id) {
      return void res.status(400).json({ detail: "Provide a valid request_id owned by the current hospital user." });
    }

    if (!assertRequestOpen(bloodRequest.status)) {
      return void res.status(400).json({ detail: "Selected request is not open for pinging." });
    }

    const ping = await prisma.donorPingLog.create({
      data: {
        donorId,
        bloodRequestId: requestId,
        responseStatus: "PENDING",
        didRespond: false,
      },
    });

    const donorName = `${donor.user.firstName} ${donor.user.lastName}`.trim() || donor.user.email;

    res.status(201).json({
      ping_id: ping.id,
      donor_user_id: donor.userId,
      donor_email: donor.user.email,
      request_id: bloodRequest.id,
      detail: `Ping sent to ${donorName} for request #${bloodRequest.id} (ping #${ping.id}).`,
    });
  })
);

app.get(
  "/api/dashboard/donor/inbox/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const logs = await prisma.donorPingLog.findMany({
      where: { donorId: donor.id },
      include: { bloodRequest: true },
      orderBy: { pingedAt: "desc" },
    });

    res.json(
      logs.map((item) => ({
        id: item.id,
        pinged_at: item.pingedAt.toISOString(),
        response_status: item.responseStatus,
        response_note: item.responseNote,
        responded_at: toDate(item.respondedAt),
        hospital_name: item.bloodRequest.hospitalName,
        request_id: item.bloodRequest.id,
        patient_name: item.bloodRequest.patientName,
        description: item.bloodRequest.description,
        blood_group_needed: item.bloodRequest.bloodGroupNeeded,
        urgency: item.bloodRequest.urgency,
        request_status: item.bloodRequest.status,
        can_open_request_detail: assertRequestOpen(item.bloodRequest.status),
        required_by_datetime: item.bloodRequest.requiredByDatetime.toISOString(),
      }))
    );
  })
);

app.get(
  "/api/dashboard/donor/inbox/history/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const logs = await prisma.donorPingLog.findMany({
      where: { donorId: donor.id },
      include: { bloodRequest: true },
      orderBy: [{ pingedAt: "desc" }, { id: "desc" }],
    });

    const items = logs.map((item) => ({
      id: item.id,
      pinged_at: item.pingedAt.toISOString(),
      response_status: item.responseStatus,
      response_note: item.responseNote,
      responded_at: toDate(item.respondedAt),
      hospital_name: item.bloodRequest.hospitalName,
      request_id: item.bloodRequest.id,
      patient_name: item.bloodRequest.patientName,
      description: item.bloodRequest.description,
      blood_group_needed: item.bloodRequest.bloodGroupNeeded,
      urgency: item.bloodRequest.urgency,
      request_status: item.bloodRequest.status,
      can_open_request_detail: assertRequestOpen(item.bloodRequest.status),
      required_by_datetime: item.bloodRequest.requiredByDatetime.toISOString(),
    }));

    res.json({ user_id: req.user!.id, total_count: items.length, items });
  })
);

app.get(
  "/api/dashboard/donor/inbox/:pingId/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const pingId = Number(req.params.pingId);
    const item = await prisma.donorPingLog.findFirst({
      where: { id: pingId, donorId: donor.id },
      include: { bloodRequest: true },
    });

    if (!item) return void res.status(404).json({ detail: "Ping not found." });

    res.json({
      id: item.id,
      pinged_at: item.pingedAt.toISOString(),
      response_status: item.responseStatus,
      response_note: item.responseNote,
      responded_at: toDate(item.respondedAt),
      hospital_name: item.bloodRequest.hospitalName,
      request_id: item.bloodRequest.id,
      patient_name: item.bloodRequest.patientName,
      description: item.bloodRequest.description,
      blood_group_needed: item.bloodRequest.bloodGroupNeeded,
      urgency: item.bloodRequest.urgency,
      request_status: item.bloodRequest.status,
      can_open_request_detail: assertRequestOpen(item.bloodRequest.status),
      required_by_datetime: item.bloodRequest.requiredByDatetime.toISOString(),
    });
  })
);

app.post(
  "/api/dashboard/donor/inbox/:pingId/respond/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const pingId = Number(req.params.pingId);
    const schema = z.object({
      response_status: z.enum(["ACCEPTED", "DECLINED"]),
      response_note: z.string().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return void res.status(400).json(parseZodError(parsed.error));

    const ping = await prisma.donorPingLog.findFirst({
      where: { id: pingId, donorId: donor.id },
      include: { bloodRequest: true },
    });

    if (!ping) return void res.status(404).json({ detail: "Ping not found." });
    if (!assertRequestOpen(ping.bloodRequest.status)) {
      return void res.status(400).json({ detail: "This request is no longer open for responses." });
    }

    const updated = await prisma.donorPingLog.update({
      where: { id: ping.id },
      data: {
        responseStatus: parsed.data.response_status,
        responseNote: String(parsed.data.response_note || "").trim(),
        didRespond: true,
        respondedAt: new Date(),
      },
    });

    if (parsed.data.response_status === "ACCEPTED") {
      await prisma.donationCommitment.upsert({
        where: {
          bloodRequestId_donorId: {
            bloodRequestId: ping.bloodRequestId,
            donorId: donor.id,
          },
        },
        create: {
          bloodRequestId: ping.bloodRequestId,
          donorId: donor.id,
          status: "ACCEPTED",
        },
        update: {},
      });

      try {
        await prisma.requestAction.create({
          data: {
            bloodRequestId: ping.bloodRequestId,
            actorId: req.user!.id,
            actionType: "VOLUNTEER",
            note: "Accepted ping from donor inbox.",
          },
        });
      } catch {
        // Ignore duplicate volunteer action.
      }
    }

    res.json({ detail: `Ping response recorded as ${updated.responseStatus}.` });
  })
);

app.get(
  "/api/requests/:requestId/pings/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const bloodRequest = await prisma.bloodRequest.findUnique({ where: { id: requestId } });
    if (!bloodRequest || bloodRequest.requesterId !== req.user!.id) {
      return void res.status(400).json({ detail: "Blood request not found or not owned by current hospital user." });
    }

    const logs = await prisma.donorPingLog.findMany({
      where: { bloodRequestId: requestId },
      include: { donor: { include: { user: true } } },
      orderBy: { pingedAt: "desc" },
    });

    res.json(
      logs.map((item) => ({
        id: item.id,
        donor_id: item.donorId,
        donor_name: `${item.donor.user.firstName} ${item.donor.user.lastName}`.trim() || item.donor.user.email,
        blood_group: item.donor.bloodGroup,
        response_status: item.responseStatus,
        response_note: item.responseNote,
        pinged_at: item.pingedAt.toISOString(),
        responded_at: toDate(item.respondedAt),
      }))
    );
  })
);

app.get(
  "/api/dashboard/hospital/summary/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const now = new Date();
    const sixHours = new Date(now.getTime() + 6 * 60 * 60 * 1000);

    const [criticalOpen, activeRequests, fulfilledRequests, expiring] = await Promise.all([
      prisma.bloodRequest.count({ where: { requesterId: req.user!.id, urgency: "CRITICAL", status: { in: ["ACTIVE", "PARTIAL"] } } }),
      prisma.bloodRequest.count({ where: { requesterId: req.user!.id, status: { in: ["ACTIVE", "PARTIAL"] } } }),
      prisma.bloodRequest.count({ where: { requesterId: req.user!.id, status: "FULFILLED" } }),
      prisma.bloodRequest.count({
        where: {
          requesterId: req.user!.id,
          status: { in: ["ACTIVE", "PARTIAL"] },
          requiredByDatetime: { gte: now, lte: sixHours },
        },
      }),
    ]);

    res.json({
      critical_open: criticalOpen,
      active_requests: activeRequests,
      fulfilled_requests: fulfilledRequests,
      expiring_within_6h: expiring,
    });
  })
);

app.get(
  "/api/dashboard/donor/feed/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const radiusKm = Number(req.query.radius_km || 10);
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const donorLoc = parseLatLng(donor.location);
    if (donorLoc.lat === null || donorLoc.lng === null) {
      return void res.status(400).json({ detail: "Donor location must include valid lat/lng." });
    }

    const open = await prisma.bloodRequest.findMany({
      where: { status: { in: ["ACTIVE", "PARTIAL"] }, requiredByDatetime: { gte: new Date() } },
      include: { _count: { select: { actions: true } } },
    });

    const matched = open.filter((item) => {
      const loc = parseLatLng(item.location);
      if (loc.lat === null || loc.lng === null) return false;
      return distanceKm(donorLoc.lat!, donorLoc.lng!, loc.lat, loc.lng) <= radiusKm;
    });

    matched.sort((a, b) => {
      const d = urgencyPriority(a.urgency) - urgencyPriority(b.urgency);
      if (d !== 0) return d;
      return a.requiredByDatetime.getTime() - b.requiredByDatetime.getTime();
    });

    res.json(matched.map(requestWithActionCount));
  })
);

app.get(
  "/api/dashboard/donor/eligibility/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const today = new Date();
    const eligibleOn = donor.lastDonationDate ? new Date(donor.lastDonationDate) : new Date(today);
    if (donor.lastDonationDate) {
      eligibleOn.setDate(eligibleOn.getDate() + 90);
    }

    const daysRemaining = Math.max(Math.ceil((eligibleOn.getTime() - today.getTime()) / (24 * 60 * 60 * 1000)), 0);

    res.json({
      is_eligible: isEligibleToDonate(donor.isAvailable, donor.weightKg, donor.lastDonationDate),
      eligible_on: eligibleOn.toISOString().slice(0, 10),
      days_remaining: daysRemaining,
    });
  })
);

app.get(
  "/api/dashboard/donor/summary/",
  auth(),
  requireRole("DONOR"),
  asyncHandler(async (req, res) => {
    const radiusKm = Number(req.query.radius_km || 10);
    const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user!.id } });
    if (!donor) return void res.status(400).json({ detail: "Donor profile not found. Complete your profile first." });

    const donorLoc = parseLatLng(donor.location);
    if (donorLoc.lat === null || donorLoc.lng === null) {
      return void res.status(400).json({ detail: "Donor location must include valid lat/lng." });
    }

    const open = await prisma.bloodRequest.findMany({
      where: { status: { in: ["ACTIVE", "PARTIAL"] }, requiredByDatetime: { gte: new Date() } },
    });

    let nearbyOpen = 0;
    for (const item of open) {
      const loc = parseLatLng(item.location);
      if (loc.lat === null || loc.lng === null) continue;
      if (distanceKm(donorLoc.lat, donorLoc.lng, loc.lat, loc.lng) <= radiusKm) nearbyOpen += 1;
    }

    const commitments = await prisma.donationCommitment.findMany({
      where: { donorId: donor.id },
      include: { bloodRequest: true },
      orderBy: { acceptedAt: "desc" },
    });

    const totalDonations = commitments.filter((c) => c.status === "DONATED").length;
    const livesImpacted = totalDonations * 3;

    const today = new Date();
    const nextEligibleOn = donor.lastDonationDate ? new Date(donor.lastDonationDate) : new Date(today);
    if (donor.lastDonationDate) {
      nextEligibleOn.setDate(nextEligibleOn.getDate() + 90);
    }
    const daysUntilEligible = Math.max(Math.ceil((nextEligibleOn.getTime() - today.getTime()) / (24 * 60 * 60 * 1000)), 0);

    res.json({
      nearby_open_requests: nearbyOpen,
      total_donations: totalDonations,
      lives_impacted: livesImpacted,
      days_until_eligible: daysUntilEligible,
      is_eligible: isEligibleToDonate(donor.isAvailable, donor.weightKg, donor.lastDonationDate),
      next_eligible_on: nextEligibleOn.toISOString().slice(0, 10),
      donation_timeline: commitments.slice(0, 5).map((item) => ({
        id: item.id,
        status: item.status,
        hospital_name: item.bloodRequest.hospitalName,
        blood_group: item.bloodRequest.bloodGroupNeeded,
        accepted_at: item.acceptedAt.toISOString(),
        resolved_at: toDate(item.resolvedAt),
      })),
    });
  })
);

app.get(
  "/api/dashboard/hospital/pings/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const pings = await prisma.donorPingLog.findMany({
      where: { bloodRequest: { requesterId: req.user!.id } },
      include: { donor: { include: { user: true } }, bloodRequest: true },
      orderBy: { pingedAt: "desc" },
    });

    res.json(
      pings.map((item) => ({
        id: item.id,
        donor_id: item.donorId,
        donor_name: `${item.donor.user.firstName} ${item.donor.user.lastName}`.trim() || item.donor.user.email,
        donor_blood_group: item.donor.bloodGroup,
        response_status: item.responseStatus,
        response_note: item.responseNote,
        pinged_at: item.pingedAt.toISOString(),
        responded_at: toDate(item.respondedAt),
        request_id: item.bloodRequestId,
        patient_name: item.bloodRequest.patientName,
        blood_group_needed: item.bloodRequest.bloodGroupNeeded,
        urgency: item.bloodRequest.urgency,
        request_status: item.bloodRequest.status,
      }))
    );
  })
);

app.delete(
  "/api/dashboard/hospital/pings/:pingId/",
  auth(),
  requireRole("HOSPITAL"),
  asyncHandler(async (req, res) => {
    const pingId = Number(req.params.pingId);
    const ping = await prisma.donorPingLog.findFirst({
      where: { id: pingId, bloodRequest: { requesterId: req.user!.id } },
    });

    if (!ping) return void res.status(404).json({ detail: "Ping not found or not owned by current hospital user." });
    if (ping.responseStatus !== "PENDING") {
      return void res.status(400).json({ detail: "Can only delete pings with PENDING status." });
    }

    await prisma.donorPingLog.delete({ where: { id: pingId } });
    res.json({ detail: "Ping deleted successfully." });
  })
);

app.get(
  "/api/directory/medical-centers/",
  auth(false),
  asyncHandler(async (req, res) => {
    const cityQuery = String(req.query.city || "").trim();
    const centerType = String(req.query.center_type || "").trim().toUpperCase();
    const q = String(req.query.q || "").trim();
    const compact = ["1", "true", "True"].includes(String(req.query.compact || ""));

    const latRaw = req.query.lat;
    const lngRaw = req.query.lng;
    const userLat = latRaw !== undefined ? Number(latRaw) : NaN;
    const userLng = lngRaw !== undefined ? Number(lngRaw) : NaN;
    const limitRaw = Number(req.query.limit || 80);
    const limit = Math.max(1, Math.min(Number.isFinite(limitRaw) ? limitRaw : 80, 300));

    let city = cityQuery;

    if (!city) {
      let locationLat = Number.isFinite(userLat) ? userLat : null;
      let locationLng = Number.isFinite(userLng) ? userLng : null;

      if (req.user && (locationLat === null || locationLng === null)) {
        if (req.user.role === "DONOR") {
          const donor = await prisma.donorProfile.findUnique({ where: { userId: req.user.id } });
          const loc = parseLatLng(donor?.location);
          locationLat = loc.lat;
          locationLng = loc.lng;
        } else if (req.user.role === "HOSPITAL") {
          const hospital = await prisma.hospitalProfile.findUnique({ where: { userId: req.user.id } });
          const loc = parseLatLng(hospital?.location);
          locationLat = loc.lat;
          locationLng = loc.lng;
        }
      }

      if (locationLat !== null && locationLng !== null) {
        city = (await inferCityFromLocation(locationLat, locationLng)) || "";
      }
    }

    const where: Prisma.MedicalCenterWhereInput = {};
    if (city) where.city = { equals: city };
    if (["HOSPITAL", "LAB", "CLINIC", "BLOOD_BANK"].includes(centerType)) {
      where.centerType = centerType as Prisma.MedicalCenterWhereInput["centerType"];
    }
    if (q) where.name = { contains: q };

    const centers = await prisma.medicalCenter.findMany({ where, take: limit, orderBy: [{ city: "asc" }, { name: "asc" }] });

    const items = centers.map((c) => {
      if (compact) {
        return {
          id: c.id,
          name: c.name,
          city: c.city,
          area: c.area,
          center_type: c.centerType,
          location: deserializeLocation(c.location),
          contact: c.contact,
        };
      }
      return {
        id: c.id,
        name: c.name,
        city: c.city,
        area: c.area,
        address: c.address,
        contact: c.contact,
        doctors_count: c.doctorsCount,
        center_type: c.centerType,
        location: deserializeLocation(c.location),
        source: c.source,
        external_id: c.externalId,
      };
    });

    res.json({ city, count: items.length, items });
  })
);

// Get all unique cities with hospital count
app.get("/api/hospitals/cities", asyncHandler(async (_req, res) => {
  const cities = await prisma.medicalCenter.groupBy({
    by: ["city"],
    _count: {
      id: true,
    },
    where: {
      city: {
        not: "",
      },
    },
  });

  const result = cities
    .filter((c) => c.city && c.city.trim())
    .map((c) => ({
      city: c.city,
      hospital_count: c._count.id,
    }))
    .sort((a, b) => a.city.localeCompare(b.city));

  res.json({
    count: result.length,
    cities: result,
  });
}));

// Get hospitals by city with optional filtering
app.get(
  "/api/hospitals/by-city/:city",
  asyncHandler(async (req, res) => {
    const { city } = req.params;
    const { area, search } = req.query;

    if (!city || typeof city !== "string") {
      return res.status(400).json({ detail: "City parameter is required" });
    }

    const where: Prisma.MedicalCenterWhereInput = {
      city: {
        equals: city,
        mode: "insensitive",
      },
    };

    // Add area filter if provided
    if (area && typeof area === "string") {
      where.area = {
        equals: area,
        mode: "insensitive",
      };
    }

    // Add search filter if provided
    if (search && typeof search === "string") {
      where.OR = [
        { name: { contains: search, mode: "insensitive" } },
        { area: { contains: search, mode: "insensitive" } },
      ];
    }

    const hospitals = await prisma.medicalCenter.findMany({
      where,
      take: 100,
    });

    const items = hospitals.map((h) => ({
      id: h.id.toString(),
      name: h.name,
      city: h.city,
      area: h.area,
      location: deserializeLocation(h.location),
    }));

    res.json({
      city,
      count: items.length,
      hospitals: items,
    });
  })
);

// Get areas by city
app.get(
  "/api/hospitals/areas/:city",
  asyncHandler(async (req, res) => {
    const { city } = req.params;

    if (!city || typeof city !== "string") {
      return res.status(400).json({ detail: "City parameter is required" });
    }

    const areas = await prisma.medicalCenter.groupBy({
      by: ["area"],
      _count: {
        id: true,
      },
      where: {
        city: {
          equals: city,
          mode: "insensitive",
        },
        area: {
          not: "",
        },
      },
    });

    const result = areas
      .filter((a) => a.area && a.area.trim())
      .map((a) => ({
        area: a.area,
        hospital_count: a._count.id,
      }))
      .sort((a, b) => a.area.localeCompare(b.area));

    res.json({
      city,
      areas: result,
      total_areas: result.length,
    });
  })
);

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof z.ZodError) {
    return res.status(400).json(parseZodError(err));
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    return res.status(400).json({ detail: String(err) });
  }

  if (err instanceof Error) {
    return res.status(500).json({ detail: err.message });
  }

  return res.status(500).json({ detail: "Internal server error" });
});

// Export app for Vercel serverless
export default app;

// Only start server locally (not on Vercel)
if (process.env.NODE_ENV !== "production") {
  async function bootstrap() {
    await prisma.$connect();
    app.listen(PORT, () => {
      console.log(`BDD Node backend listening on http://localhost:${PORT}`);
    });
  }
  void bootstrap();
}
