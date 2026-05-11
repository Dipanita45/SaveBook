
import { NextResponse } from "next/server";
import dbConnect from "@/lib/db/mongodb";
import Notes from "@/lib/models/Notes";
import { verifyJwtToken } from "@/lib/utils/jwtAuth";

export async function PUT(request, { params }) {
    try {
        const { id } = await params;
        await dbConnect();

        const token = request.cookies.get("authToken");
        if (!token) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const decoded = await verifyJwtToken(token.value);
        if (!decoded || !decoded.success) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const note = await Notes.findById(id);
        if (!note) {
            return NextResponse.json({ error: "Note not found" }, { status: 404 });
        }

        if (note.user.toString() !== decoded.userId) {
            return NextResponse.json({ error: "Not authorized" }, { status: 401 });
        }

        const body = await request.json().catch(() => ({}));

        note.isPublic = !note.isPublic;

        if (note.isPublic && body.shareEncryptedContent) {
            // Client encrypted the note with a random share key and embeds the key in the URL fragment
            note.shareEncryptedContent = body.shareEncryptedContent;
        } else if (!note.isPublic) {
            note.shareEncryptedContent = null;
        }

        await note.save();

        return NextResponse.json({ isPublic: note.isPublic, _id: note._id });
    } catch (error) {
        console.error(error);
        return NextResponse.json({ error: "Server error" }, { status: 500 });
    }
}
