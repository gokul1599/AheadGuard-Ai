import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

export async function GET() {
  try {
    const filePath = path.join(process.cwd(), "public", "extension-release.json");
    if (!fs.existsSync(filePath)) {
      return NextResponse.json(
        { error: "Extension release metadata not found" },
        { status: 404 }
      );
    }

    const content = fs.readFileSync(filePath, "utf8");
    const data = JSON.parse(content);

    return NextResponse.json(data, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=60, s-maxage=300",
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to read extension release metadata", detail: String(error) },
      { status: 500 }
    );
  }
}
