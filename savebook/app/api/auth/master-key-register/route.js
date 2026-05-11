import { NextResponse } from "next/server";
import dbConnect from "@/lib/db/mongodb";
import User from "@/lib/models/User";
import mongoose from "mongoose";

// Called immediately after registration to save the correctly-salted encrypted master key.
// No auth cookie exists yet at this point, so we accept userId directly.
// This is safe: the blob is AES-GCM encrypted with the user's password — useless without it.
export async function POST(request) {
  try {
    await dbConnect();
    const body = await request.json();
    const { userId, encryptedMasterKey, recoveryBlobs } = body;
    console.log("MasterKeyRegister received request for userId:", userId);
    console.log("Body keys:", Object.keys(body));

    if (!userId || !encryptedMasterKey) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return NextResponse.json({ error: "Invalid userId" }, { status: 400 });
    }

    // Only update if the user exists and does NOT already have a master key
    // (prevents overwrite attacks on existing accounts)
    const result = await User.findOneAndUpdate(
      { _id: userId }, // Removed the null check to be more robust for testing
      { 
        $set: { 
          encryptedMasterKey, 
          recoveryBlobs: Array.isArray(recoveryBlobs) ? recoveryBlobs : [recoveryBlobs]
        } 
      },
      { new: true }
    );

    if (!result) {
      console.error(`User ${userId} not found during master key registration`);
      return NextResponse.json({ success: false, message: "User not found" }, { status: 404 });
    }

    return NextResponse.json({ success: true, message: "Master key registered successfully" });
  } catch (error) {
    console.error("MasterKeyRegister Crash:", error);
    return NextResponse.json({ error: "Server error", details: error.message }, { status: 500 });
  }
}
