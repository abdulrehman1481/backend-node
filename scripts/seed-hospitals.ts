import fs from "fs";
import path from "path";
import { PrismaClient } from "@prisma/client";
import "dotenv/config";

const prisma = new PrismaClient();

// Parse CSV file - handles both standard headers and edge cases
function parseCSV(filePath: string): Record<string, string>[] {
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n").filter((line) => line.trim());

  if (lines.length === 0) return [];

  const headers = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(",").map((v) => v.trim());
    const row: Record<string, string> = {};

    headers.forEach((header, index) => {
      row[header] = values[index] || "";
    });

    rows.push(row);
  }

  return rows;
}

async function seedHospitals() {
  try {
    console.log("🏥 Seeding hospital data from CSV files...\n");

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
    let idCounter = 1000n;

    for (const hospital of hospitals) {
      try {
        const hospitalName = hospital["hospital name"] || hospital.name || hospital["hospital_name"] || "";
        
        if (!hospitalName.trim()) {
          skippedCount++;
          continue;
        }

        // Generate a unique ID: use hash of hospital name, fallback to counter
        let id: bigint;
        if (hospitalName) {
          const hashValue = hospitalName
            .split("")
            .reduce((acc, char) => acc + char.charCodeAt(0), 0);
          // Ensure it's a valid BigInt by taking absolute value and ensuring it's positive
          id = BigInt(Math.abs(hashValue) || 1) + 1000n;
        } else {
          id = idCounter;
          idCounter++;
        }

        // Default location (Pakistan center)
        const latitude = parseFloat(hospital.latitude || "") || 24.8607;
        const longitude = parseFloat(hospital.longitude || "") || 67.0011;
        
        const location = {
          lat: latitude,
          lng: longitude,
        };

        const city = hospital.city || hospital.district || "";
        const area = hospital.area || hospital.tehsil || "";
        const address = hospital.address || "";
        const contact = hospital.contact || "";
        const doctorsCount = hospital.doctors ? parseInt(hospital.doctors) : null;

        await prisma.medicalCenter.upsert({
          where: { id },
          update: {
            name: hospitalName,
            city,
            area,
            address,
            contact,
            ...(doctorsCount && { doctorsCount }),
            location,
          },
          create: {
            id,
            name: hospitalName,
            city,
            area,
            address,
            contact,
            ...(doctorsCount && { doctorsCount }),
            location,
          },
        });

        seededCount++;
        if (seededCount % 50 === 0) {
          console.log(`⏳ Seeded ${seededCount} hospitals...`);
        }
      } catch (error) {
        skippedCount++;
        if (skippedCount <= 5) {
          console.warn(
            `⚠️  Skipping hospital:`,
            (error as Error).message
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
