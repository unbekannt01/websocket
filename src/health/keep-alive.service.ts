/* eslint-disable prettier/prettier */
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import * as http from 'http';
import * as https from 'https';

@Injectable()
export class KeepAliveService implements OnModuleInit {
  private readonly logger = new Logger(KeepAliveService.name);
  private healthUrl: string;
  private pingCount = 0;

  onModuleInit() {
    // Build the health URL from environment or fallback to localhost
    const port = process.env.PORT || 3000;
    const baseUrl = process.env.RENDER_EXTERNAL_URL
      || process.env.BACKEND_URL
      || `http://localhost:${port}`;

    this.healthUrl = `${baseUrl}/health`;
    this.logger.log(`🏓 Keep-alive service initialized. Pinging: ${this.healthUrl}`);
  }

  /**
   * Self-ping every 4 minutes to keep the server awake.
   * 
   * Why 4 minutes?
   * - Most free-tier platforms (Render, Railway, etc.) sleep after 15 minutes of inactivity
   * - UptimeRobot free plan only pings every 5 minutes
   * - 4 minutes gives a comfortable margin before any sleep timer kicks in
   * 
   * Note: If the server is already sleeping, this cron won't run (it's in-process).
   * That's why external tools like UptimeRobot are still recommended as a backup.
   */
  @Cron(CronExpression.EVERY_5_MINUTES)
  handleKeepAlive() {
    this.pingCount++;
    const client = this.healthUrl.startsWith('https') ? https : http;

    client.get(this.healthUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        this.logger.log(
          `✅ Keep-alive ping #${this.pingCount} successful (status: ${res.statusCode})`,
        );
      });
    }).on('error', (err) => {
      this.logger.warn(
        `⚠️ Keep-alive ping #${this.pingCount} failed: ${err.message}`,
      );
    });
  }
}
