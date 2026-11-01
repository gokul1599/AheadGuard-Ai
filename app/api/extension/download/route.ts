import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

export async function GET() {
  try {
    const zipPath = path.join(process.cwd(), "public", "aheadguard-ai-chrome-extension.zip");
    if (!fs.existsSync(zipPath)) {
      return NextResponse.json(
        { error: "Extension archive not found" },
        { status: 404 }
      );
    }

    const fileBuffer = fs.readFileSync(zipPath);

    return new NextResponse(fileBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": 'attachment; filename="aheadguard-ai-chrome-extension.zip"',
        "Content-Length": fileBuffer.length.toString(),
        "Cache-Control": "public, max-age=3600, s-maxage=86400",
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to download extension archive", detail: String(error) },
      { status: 500 }
    );
  }
}
