import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AheadGuard AI — Pre-Action Digital Safety Guardian",
  description:
    "AheadGuard AI investigates risky destinations, evaluates observable evidence, and simulates consequences before you commit sensitive actions.",
};

export const viewport: Viewport = {
  themeColor: "#040812",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
