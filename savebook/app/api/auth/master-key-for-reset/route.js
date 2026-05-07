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
    }).select("_id encryptedMasterKey");

    if (!user || !user.encryptedMasterKey) {
      // Return empty — client will skip re-wrap gracefully
      return NextResponse.json({ encryptedMasterKey: null, userId: null });
    }

    return NextResponse.json({
      encryptedMasterKey: user.encryptedMasterKey,
      userId: user._id.toString(),
    });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
