import fs from "fs";
import path from "path";
import { PrismaClient } from "@prisma/client";
import "dotenv/config";

const prisma = new PrismaClient();

interface DjangoModel {
  model: string;
  pk: number;
  fields: Record<string, unknown>;
}

// Transform Django field names to Prisma field names
function transformUser(django: any): any {
  return {
    id: BigInt(django.pk),
    passwordHash: django.fields.password,
    lastLogin: django.fields.last_login ? new Date(django.fields.last_login) : null,
    isSuperuser: django.fields.is_superuser,
    username: django.fields.username,
    firstName: django.fields.first_name || "",
    lastName: django.fields.last_name || "",
    email: django.fields.email,
    isStaff: django.fields.is_staff,
    isActive: django.fields.is_active,
    dateJoined: new Date(django.fields.date_joined),
    role: django.fields.role || "DONOR",
    phoneNumber: django.fields.phone_number || "",
    isPhoneVerified: django.fields.is_phone_verified || false,
    isEmailVerified: django.fields.is_email_verified || false,
    isBanned: django.fields.is_banned || false,
  };
}

function transformDonorProfile(django: any): any {
  return {
    id: BigInt(django.pk),
    userId: BigInt(django.fields.user_id),
    bloodGroup: django.fields.blood_group,
    dateOfBirth: new Date(django.fields.date_of_birth),
    weightKg: parseFloat(django.fields.weight_kg),
    gender: django.fields.gender,
    isAvailable: django.fields.is_available ?? true,
    lastDonationDate: django.fields.last_donation_date ? new Date(django.fields.last_donation_date) : null,
    location: django.fields.location,
    locationUpdatedAt: new Date(django.fields.location_updated_at || new Date()),
  };
}

function transformHospitalProfile(django: any): any {
  return {
    id: BigInt(django.pk),
    userId: BigInt(django.fields.user_id),
    facilityName: django.fields.facility_name,
    licenseNumber: django.fields.license_number,
    isVerifiedByAdmin: django.fields.is_verified_by_admin ?? false,
    nodalOfficerName: django.fields.nodal_officer_name,
    emergencyPhone: django.fields.emergency_phone,
    location: django.fields.location,
  };
}

function transformBloodRequest(django: any): any {
  return {
    id: BigInt(django.pk),
    requesterId: BigInt(django.fields.requester_id),
    patientName: django.fields.patient_name,
    description: django.fields.description || "",
    patientAge: django.fields.patient_age || null,
    bloodGroupNeeded: django.fields.blood_group_needed,
    unitsRequired: django.fields.units_required || 1,
    unitsFulfilled: django.fields.units_fulfilled || 0,
    urgency: django.fields.urgency || "STANDARD",
    status: django.fields.status || "ACTIVE",
    requiredByDatetime: new Date(django.fields.required_by_datetime),
    hospitalName: django.fields.hospital_name,
    location: django.fields.location,
    createdAt: new Date(django.fields.created_at),
    updatedAt: new Date(django.fields.updated_at),
  };
}

function transformDonationCommitment(django: any): any {
  return {
    id: BigInt(django.pk),
    donorId: BigInt(django.fields.donor_id),
    requestId: BigInt(django.fields.request_id),
    unitsCommitted: django.fields.units_committed || 1,
    status: django.fields.status || "PENDING",
    commitmentDate: new Date(django.fields.commitment_date),
  };
}

function transformRequestAction(django: any): any {
  return {
    id: BigInt(django.pk),
    requestId: BigInt(django.fields.request_id),
    actorId: BigInt(django.fields.actor_id),
    actionType: django.fields.action_type,
    actionDate: new Date(django.fields.action_date),
  };
}

function transformRequestComment(django: any): any {
  return {
    id: BigInt(django.pk),
    requestId: BigInt(django.fields.request_id),
    authorId: BigInt(django.fields.author_id),
    content: django.fields.content,
    createdAt: new Date(django.fields.created_at),
  };
}

function transformDonorPingLog(django: any): any {
  return {
    id: BigInt(django.pk),
    donorId: BigInt(django.fields.donor_id),
    requestId: BigInt(django.fields.request_id),
    pingSentAt: new Date(django.fields.ping_sent_at),
    responseStatus: django.fields.response_status || "PENDING",
  };
}

function transformMedicalCenter(django: any): any {
  return {
    id: BigInt(django.pk),
    name: django.fields.name,
    city: django.fields.city || "",
    area: django.fields.area || "",
    location: django.fields.location,
  };
}

async function seedDatabase() {
  try {
    console.log("📥 Reading Django export file...");
    const filePath = path.join(process.cwd(), "full_export.json");
    
    if (!fs.existsSync(filePath)) {
      console.error("❌ full_export.json not found");
      process.exit(1);
    }

    const fileContent = fs.readFileSync(filePath, "utf-8");
    const data: DjangoModel[] = JSON.parse(fileContent);

    console.log(`✅ Loaded ${data.length} Django models`);

    // Group data by model type
    const byModel: Record<string, DjangoModel[]> = {};
    for (const item of data) {
      if (!byModel[item.model]) byModel[item.model] = [];
      byModel[item.model].push(item);
    }

    // Seed users first (dependency for other models)
    if (byModel["core.user"]) {
      console.log(`\n👤 Seeding ${byModel["core.user"].length} users...`);
      for (const item of byModel["core.user"]) {
        try {
          const userData = transformUser(item);
          await prisma.user.upsert({
            where: { id: userData.id },
            update: userData,
            create: userData,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping user ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Users seeded");
    }

    // Seed donor profiles
    if (byModel["core.donorprofile"]) {
      console.log(`\n🩸 Seeding ${byModel["core.donorprofile"].length} donor profiles...`);
      for (const item of byModel["core.donorprofile"]) {
        try {
          const data = transformDonorProfile(item);
          await prisma.donorProfile.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping donor profile ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Donor profiles seeded");
    }

    // Seed hospital profiles
    if (byModel["core.hospitalprofile"]) {
      console.log(`\n🏥 Seeding ${byModel["core.hospitalprofile"].length} hospital profiles...`);
      for (const item of byModel["core.hospitalprofile"]) {
        try {
          const data = transformHospitalProfile(item);
          await prisma.hospitalProfile.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping hospital profile ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Hospital profiles seeded");
    }

    // Seed blood requests
    if (byModel["core.bloodrequest"]) {
      console.log(`\n🔴 Seeding ${byModel["core.bloodrequest"].length} blood requests...`);
      for (const item of byModel["core.bloodrequest"]) {
        try {
          const data = transformBloodRequest(item);
          await prisma.bloodRequest.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping blood request ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Blood requests seeded");
    }

    // Seed donation commitments
    if (byModel["core.donationcommitment"]) {
      console.log(`\n✅ Seeding ${byModel["core.donationcommitment"].length} donation commitments...`);
      for (const item of byModel["core.donationcommitment"]) {
        try {
          const data = transformDonationCommitment(item);
          await prisma.donationCommitment.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping donation commitment ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Donation commitments seeded");
    }

    // Seed request actions
    if (byModel["core.requestaction"]) {
      console.log(`\n📋 Seeding ${byModel["core.requestaction"].length} request actions...`);
      for (const item of byModel["core.requestaction"]) {
        try {
          const data = transformRequestAction(item);
          await prisma.requestAction.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping request action ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Request actions seeded");
    }

    // Seed request comments
    if (byModel["core.requestcomment"]) {
      console.log(`\n💬 Seeding ${byModel["core.requestcomment"].length} request comments...`);
      for (const item of byModel["core.requestcomment"]) {
        try {
          const data = transformRequestComment(item);
          await prisma.requestComment.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping request comment ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Request comments seeded");
    }

    // Seed donor ping logs
    if (byModel["core.donorpinglog"]) {
      console.log(`\n🔔 Seeding ${byModel["core.donorpinglog"].length} donor ping logs...`);
      for (const item of byModel["core.donorpinglog"]) {
        try {
          const data = transformDonorPingLog(item);
          await prisma.donorPingLog.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping donor ping log ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Donor ping logs seeded");
    }

    // Seed medical centers
    if (byModel["core.medicalcenter"]) {
      console.log(`\n🏨 Seeding ${byModel["core.medicalcenter"].length} medical centers...`);
      for (const item of byModel["core.medicalcenter"]) {
        try {
          const data = transformMedicalCenter(item);
          await prisma.medicalCenter.upsert({
            where: { id: data.id },
            update: data,
            create: data,
          });
        } catch (e) {
          console.warn(`⚠️  Skipping medical center ${item.pk}:`, (e as Error).message);
        }
      }
      console.log("✅ Medical centers seeded");
    }

    console.log("\n🎉 Database seeding completed!");
  } catch (error) {
    console.error("❌ Seeding failed:", error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

seedDatabase();
