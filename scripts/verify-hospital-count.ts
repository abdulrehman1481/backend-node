/// <reference types="node" />

import "dotenv/config";

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const totalMedicalCenters = await prisma.medicalCenter.count();
  const totalHospitals = await prisma.medicalCenter.count({
    where: { centerType: "HOSPITAL" },
  });
  const hospitalsWithCity = await prisma.medicalCenter.count({
    where: { centerType: "HOSPITAL", city: { not: "" } },
  });

  console.log(
    JSON.stringify(
      {
        total_medical_centers: totalMedicalCenters,
        total_hospitals: totalHospitals,
        hospitals_with_city: hospitalsWithCity,
      },
      null,
      2
    )
  );
}

main()
  .catch((error) => {
    console.error("Verification failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
