import { NextResponse } from "next/server";
import dbConnect from "@/lib/db/mongodb";
import User from "@/lib/models/User";

// Returns the encrypted master key blob + userId for a given identifier
// This is safe to expose: the blob is useless without the recovery code to decrypt it
export async function POST(request) {
  try {
    await dbConnect();
    const { identifier } = await request.json();
    if (!identifier) return NextResponse.json({ error: "Identifier required" }, { status: 400 });

    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    }).select("_id recoveryBlobs");

    if (!user) {
      console.log(`User not found for identifier: ${identifier}`);
      return NextResponse.json({ recoveryBlobs: null, userId: null });
    }

    if (!user.recoveryBlobs || user.recoveryBlobs.length === 0) {
      console.log(`No recovery blobs found for user: ${user._id}`);
      return NextResponse.json({ recoveryBlobs: null, userId: null });
    }

    console.log(`Fetching master key for reset (${identifier}). Blobs found: ${user.recoveryBlobs.length}`);

    return NextResponse.json({
      recoveryBlobs: user.recoveryBlobs,
      userId: user._id.toString(),
    });
  } catch (error) {
    console.error("Master key for reset error:", error);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
