/// <reference types="node" />

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";
import "dotenv/config";

const prisma = new PrismaClient();

// Parse CSV with support for quoted fields containing commas/newlines.
function parseCSV(filePath: string): Record<string, string>[] {
  const content = fs.readFileSync(filePath, "utf-8").replace(/^\uFEFF/, "");
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentCell = "";
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    const next = content[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        currentCell += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (ch === "," && !inQuotes) {
      currentRow.push(currentCell.trim());
      currentCell = "";
      continue;
    }

    if ((ch === "\n" || ch === "\r") && !inQuotes) {
      if (ch === "\r" && next === "\n") {
        i++;
      }
      currentRow.push(currentCell.trim());
      currentCell = "";
      if (currentRow.some((cell) => cell.length > 0)) {
        rows.push(currentRow);
      }
      currentRow = [];
      continue;
    }

    currentCell += ch;
  }

  if (currentCell.length > 0 || currentRow.length > 0) {
    currentRow.push(currentCell.trim());
    if (currentRow.some((cell) => cell.length > 0)) {
      rows.push(currentRow);
    }
  }

  if (rows.length === 0) return [];

  const headers = rows[0].map((h) => h.trim().toLowerCase());
  const mappedRows: Record<string, string>[] = [];

  for (let i = 1; i < rows.length; i++) {
    const values = rows[i];
    const row: Record<string, string> = {};
    headers.forEach((header, index) => {
      row[header] = values[index] || "";
    });
    mappedRows.push(row);
  }

  return mappedRows;
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function parseDoctorsCount(rawValue: string): number | null {
  if (!rawValue) return null;
  const cleaned = rawValue.replace(/[^0-9]/g, "");
  if (!cleaned) return null;
  const num = Number(cleaned);
  if (!Number.isFinite(num) || num <= 0) return null;
  return num;
}

function makeExternalId(parts: string[]): string {
  const digest = crypto.createHash("sha1").update(parts.join("|").toLowerCase()).digest("hex");
  return `csv:${digest}`;
}

async function upsertWithRetry(data: {
  name: string;
  city: string;
  area: string;
  address: string;
  contact: string;
  doctorsCount: number | null;
  location: { lat: number; lng: number } | Record<string, never>;
  externalId: string;
}) {
  const maxAttempts = 3;
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt += 1;
    try {
      await prisma.medicalCenter.upsert({
        where: { externalId: data.externalId },
        update: {
          name: data.name,
          city: data.city,
          area: data.area,
          address: data.address,
          contact: data.contact,
          ...(data.doctorsCount !== null ? { doctorsCount: data.doctorsCount } : {}),
          location: data.location,
          centerType: "HOSPITAL",
          source: "csv_seed",
          externalId: data.externalId,
        },
        create: {
          name: data.name,
          city: data.city,
          area: data.area,
          address: data.address,
          contact: data.contact,
          ...(data.doctorsCount !== null ? { doctorsCount: data.doctorsCount } : {}),
          location: data.location,
          centerType: "HOSPITAL",
          source: "csv_seed",
          externalId: data.externalId,
        },
      });
      return;
    } catch (error) {
      const message = String((error as Error).message || "");
      const isTransient =
        message.includes("Can't reach database server") ||
        message.includes("Timed out") ||
        message.includes("ECONN") ||
        message.includes("Connection reset");
      if (!isTransient || attempt >= maxAttempts) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
    }
  }
}

async function seedHospitals() {
  try {
    console.log("🏥 Seeding hospital data from CSV files...\n");

    // Ensure Postgres sequence is aligned with existing IDs (important after manual ID inserts).
    try {
      await prisma.$executeRawUnsafe(`
        SELECT setval(
          pg_get_serial_sequence('"core_medicalcenter"', 'id'),
          COALESCE((SELECT MAX(id) FROM "core_medicalcenter"), 1),
          true
        );
      `);
    } catch {
      // Continue even if sequence sync is unavailable; upsert logic still handles most rows.
    }

    // Try multiple paths for the hospital details CSV
    const possiblePaths = [
      path.join(process.cwd(), "archive/pakistan_hospitals_details.csv"),
      path.join(process.cwd(), "../archive/pakistan_hospitals_details.csv"),
      path.join(__dirname, "../../archive/pakistan_hospitals_details.csv"),
      "D:\\appdev\\bdd\\archive\\pakistan_hospitals_details.csv",
    ];

    let detailsPath = "";
    for (const p of possiblePaths) {
      if (fs.existsSync(p)) {
        detailsPath = p;
        break;
      }
    }

    if (!detailsPath) {
      console.error("❌ Hospital CSV file not found in any of these locations:");
      possiblePaths.forEach((p) => console.error(`  - ${p}`));
      process.exit(1);
    }

    console.log(`📖 Reading hospital details from: ${detailsPath}`);
    const hospitals = parseCSV(detailsPath);
    
    console.log(`✅ Loaded ${hospitals.length} hospitals from CSV\n`);

    let seededCount = 0;
    let skippedCount = 0;
    let connectivityFailures = 0;

    for (const hospital of hospitals) {
      try {
        const hospitalName = normalizeText(hospital["hospital name"] || hospital.name || hospital["hospital_name"] || "");
        
        if (!hospitalName.trim()) {
          skippedCount++;
          continue;
        }

        const latitude = Number.parseFloat(hospital.latitude || "");
        const longitude = Number.parseFloat(hospital.longitude || "");

        // Do not assign fake fallback coordinates; keep location empty if source has no valid lat/lng.
        const hasValidCoordinates =
          Number.isFinite(latitude) &&
          Number.isFinite(longitude) &&
          latitude >= -90 &&
          latitude <= 90 &&
          longitude >= -180 &&
          longitude <= 180 &&
          !(latitude === 0 && longitude === 0);

        const location: { lat: number; lng: number } | Record<string, never> = hasValidCoordinates
          ? {
              lat: latitude,
              lng: longitude,
            }
          : ({} as Record<string, never>);

        const city = normalizeText(hospital.city || hospital.district || "") || "Unknown";
        const area = normalizeText(hospital.area || hospital.tehsil || "");
        const address = normalizeText(hospital.address || "");
        const contact = normalizeText(hospital.contact || "");
        const doctorsCount = parseDoctorsCount(hospital.doctors || "");

        // Use deterministic external_id so each hospital row is uniquely addressable across re-runs.
        const externalId = makeExternalId([hospitalName, city, area, address]);

        await upsertWithRetry({
          name: hospitalName,
          city,
          area,
          address,
          contact,
          doctorsCount,
          location,
          externalId,
        });

        seededCount++;
        if (seededCount % 50 === 0) {
          console.log(`⏳ Seeded ${seededCount} hospitals...`);
        }
      } catch (error) {
        skippedCount++;
        const message = String((error as Error).message || "");
        if (message.includes("Can't reach database server")) {
          connectivityFailures++;
        }
        if (skippedCount <= 5) {
          console.warn(
            `⚠️  Skipping hospital:`,
            (error as Error).message
          );
        }

        if (connectivityFailures >= 5) {
          throw new Error(
            "Neon connectivity failed repeatedly (5 times). Aborting seed to prevent partial import."
          );
        }
      }
    }

    console.log(`\n✅ Seeding completed!`);
    console.log(`📊 Total seeded: ${seededCount}`);
    console.log(`⏭️  Skipped: ${skippedCount}`);
    console.log(`\n🎉 Hospital data is now in database!`);
  } catch (error) {
    console.error("❌ Hospital seeding failed:", error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

seedHospitals();
