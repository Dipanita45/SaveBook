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
    const { userId, encryptedMasterKey } = await request.json();

    if (!userId || !encryptedMasterKey) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return NextResponse.json({ error: "Invalid userId" }, { status: 400 });
    }

    // Only update if the user exists and does NOT already have a master key
    // (prevents overwrite attacks on existing accounts)
    const result = await User.findOneAndUpdate(
      { _id: userId, encryptedMasterKey: null },
      { encryptedMasterKey }
    );

    if (!result) {
      // Either user not found or already has a key — both are fine, just no-op
      return NextResponse.json({ success: true });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
