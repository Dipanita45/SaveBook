import { NextResponse } from "next/server";
import dbConnect from "@/lib/db/mongodb";
import User from "@/lib/models/User";
import { verifyJwtToken } from "@/lib/utils/jwtAuth";

export async function POST(request) {
  try {
    await dbConnect();
    const token = request.cookies.get("authToken");
    if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const decoded = await verifyJwtToken(token.value);
    if (!decoded?.success) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { encryptedMasterKey } = await request.json();
    if (!encryptedMasterKey) return NextResponse.json({ error: "Missing encryptedMasterKey" }, { status: 400 });

    await User.findByIdAndUpdate(decoded.userId, { encryptedMasterKey });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
