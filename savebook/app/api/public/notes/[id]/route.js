
import { NextResponse } from "next/server";
import dbConnect from "@/lib/db/mongodb";
import Notes from "@/lib/models/Notes";

export async function GET(request, { params }) {
    try {
        const { id } = await params;
        await dbConnect();

        const note = await Notes.findById(id).select("isPublic shareEncryptedContent tag date");

        if (!note) {
            return NextResponse.json({ error: "Note not found" }, { status: 404 });
        }

        if (!note.isPublic) {
            return NextResponse.json({ error: "Note is private" }, { status: 403 });
        }

        if (!note.shareEncryptedContent) {
            return NextResponse.json({ error: "Note has no shareable content" }, { status: 404 });
        }

        return NextResponse.json({
            shareEncryptedContent: note.shareEncryptedContent,
            tag: note.tag,
            date: note.date,
        });
    } catch (error) {
        console.error(error);
        return NextResponse.json({ error: "Server error" }, { status: 500 });
    }
}
