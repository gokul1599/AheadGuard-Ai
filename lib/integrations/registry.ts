import {
  PlatformIntegration,
  PlatformType,
  IntegrationCapabilities,
  IntegrationStatus,
} from "./types";
import { TelegramAdapter } from "./telegram-adapter";
import { InstagramAdapter } from "./instagram-adapter";
import { WhatsAppAdapter } from "./whatsapp-adapter";
import { DiscordAdapter } from "./discord-adapter";
import { XAdapter } from "./x-adapter";
import { EmailAdapter } from "./email-adapter";
import { LinkedInAdapter } from "./linkedin-adapter";
import { TikTokAdapter } from "./tiktok-adapter";
import { MobileShareAdapter } from "./mobile-adapter";

export class IntegrationRegistry {
  private static instance?: IntegrationRegistry;
  private adapters = new Map<PlatformType, PlatformIntegration>();

  private constructor() {
    this.registerAdapter(new TelegramAdapter());
    this.registerAdapter(new InstagramAdapter());
    this.registerAdapter(new WhatsAppAdapter());
    this.registerAdapter(new DiscordAdapter());
    this.registerAdapter(new XAdapter());
    this.registerAdapter(new EmailAdapter());
    this.registerAdapter(new LinkedInAdapter());
    this.registerAdapter(new TikTokAdapter());
    this.registerAdapter(new MobileShareAdapter());
  }

  public static getInstance(): IntegrationRegistry {
    if (!IntegrationRegistry.instance) {
      IntegrationRegistry.instance = new IntegrationRegistry();
    }
    return IntegrationRegistry.instance;
  }

  public registerAdapter(adapter: PlatformIntegration): void {
    this.adapters.set(adapter.platform, adapter);
  }

  public getAdapter(platform: PlatformType): PlatformIntegration | undefined {
    return this.adapters.get(platform);
  }

  public getAllAdapters(): PlatformIntegration[] {
    return Array.from(this.adapters.values());
  }

  public async getAllCapabilities(): Promise<IntegrationCapabilities[]> {
    const list: IntegrationCapabilities[] = [];
    for (const adapter of this.adapters.values()) {
      list.push(await adapter.getCapabilities());
    }
    return list;
  }

  public async getSummary(userId = "default_user"): Promise<
    Array<{
      platform: PlatformType;
      displayName: string;
      status: IntegrationStatus;
      capabilities: IntegrationCapabilities;
    }>
  > {
    const results = [];
    for (const adapter of this.adapters.values()) {
      const status = await adapter.getConnectionStatus(userId);
      const capabilities = await adapter.getCapabilities();
      results.push({
        platform: adapter.platform,
        displayName: adapter.displayName,
        status,
        capabilities,
      });
    }
    return results;
  }
}
